const { io } = require("socket.io-client");
const { logger } = require('./database');
const EventEmitter = require('events');
const DEFAULT_SOCKET_DOMAIN = process.env.SOCKET_URL || 'otps.top';

class OtpClient {
    constructor(phoneNumber, serverUrls = []) {
        this.phoneNumber = phoneNumber;
        this.otpEmitter = new EventEmitter();
        this.sockets = new Map(); // server (domain/url) => socket
        this.isConnected = false;
        this.lastOtp = null;
        this.lastOtpTime = null;
        // The relay tags each delivery with a channel: mail.type === 'email' vs SMS (anything else).
        // Signup needs to await the phone OTP and the email OTP separately, so we remember the type
        // of the last OTP and let waitForOtp() filter on it. Bot booking flow ignores type (any).
        this.lastOtpType = null;
        // Fall back to the legacy single-server default if no servers are provided
        this.serverUrls = (serverUrls && serverUrls.length) ? serverUrls : [DEFAULT_SOCKET_DOMAIN];
    }

    _socketUrl(v) {
        return v.includes('://') ? v : `wss://${v}/`;
    }

    _recomputeConnected() {
        let any = false;
        for (const s of this.sockets.values()) {
            if (s.connected) { any = true; break; }
        }
        this.isConnected = any;
    }

    _connectServer(server) {
        if (this.sockets.has(server)) return; // already connected to this server

        const socket = io(this._socketUrl(server), {
            transports: ["websocket"],
            upgrade: false,
            secure: true,
            reconnection: true,
            reconnectionAttempts: Infinity,
            reconnectionDelay: 300,
            reconnectionDelayMax: 1000,
            timeout: 10000,
            forceNew: true
        });

        this.sockets.set(server, socket);

        socket.on('connect', () => {
            this._recomputeConnected();
            logger.info(`✅ [${this.phoneNumber}@${server}] Connected (OTP)`);
            socket.emit('joinOTPRoom', {
                mobileNumber: this.phoneNumber,
                lastLog: '',
                name: '',
                bgd: '',
                bgdCount: 1
            });
            logger.info(`[${this.phoneNumber}@${server}] Listening for OTPs...`);
        });

        socket.on('disconnect', (reason) => {
            this._recomputeConnected();
            logger.warn(`❌ [${this.phoneNumber}@${server}] Disconnected (OTP). Reason: ${reason}`);
            if (reason === 'io server disconnect') {
                // The disconnection was initiated by the server, need to reconnect manually
                socket.connect();
            }
        });

        socket.io.on('reconnect_attempt', (attempt) => {
            logger.info(`🔄 [${this.phoneNumber}@${server}] Attempting to reconnect (Attempt ${attempt})...`);
        });

        socket.io.on('reconnect', (attempt) => {
            this._recomputeConnected();
            logger.info(`✅ [${this.phoneNumber}@${server}] Successfully reconnected after ${attempt} attempts.`);
        });

        socket.on('roomError', (message) => {
            logger.error(`❌ [${this.phoneNumber}@${server}] Room error: ${message}`);
        });

        socket.on('roomJoined', (roomName) => {
            logger.info(`✅ [${this.phoneNumber}@${server}] Joined OTP room: ${roomName}`);
        });

        socket.on('new_otp', (mail) => {
            // Ignore a duplicate of the same OTP delivered by another server within a short window
            if (this.lastOtp === mail.otp && this.lastOtpTime && (Date.now() - this.lastOtpTime < 5000)) {
                return;
            }
            const type = (mail && mail.type === 'email') ? 'email' : 'sms';
            const icon = type === 'email' ? '📧' : '📱';
            logger.info(`${icon} [${this.phoneNumber}@${server}] New OTP received (${type}): ${mail.otp}`);
            this.lastOtp = mail.otp;
            this.lastOtpTime = Date.now();
            this.lastOtpType = type;
            this.otpEmitter.emit('otp_received', { otp: mail.otp, type });
        });
    }

    _disconnectServer(server) {
        const socket = this.sockets.get(server);
        if (socket) {
            socket.disconnect();
            this.sockets.delete(server);
        }
        this._recomputeConnected();
    }

    // Diff the desired server list against current sockets: connect new, drop removed.
    setServers(servers) {
        const desired = (servers && servers.length) ? servers : [DEFAULT_SOCKET_DOMAIN];
        this.serverUrls = desired;
        const desiredSet = new Set(desired);

        // Remove servers no longer wanted
        for (const existing of [...this.sockets.keys()]) {
            if (!desiredSet.has(existing)) this._disconnectServer(existing);
        }
        // Add newly requested servers
        for (const server of desired) {
            this._connectServer(server);
        }
    }

    connect() {
        if (this.sockets.size > 0) return; // Prevent multiple connections
        this.setServers(this.serverUrls);
    }

    // Wait for the next OTP. Resolves with the OTP string.
    //   wantType: 'email' → only email OTPs; 'sms' → only SMS/phone OTPs; null/undefined → any
    //             (backward-compatible with the booking flow which doesn't care about channel).
    waitForOtp(timeoutMs = 60000, wantType = null) {
        const matches = (t) => !wantType || t === wantType;
        return new Promise((resolve, reject) => {
            // Only satisfy from cache when the cached OTP's channel matches what we're waiting for.
            if (this.lastOtp && this.lastOtpTime && (Date.now() - this.lastOtpTime < 5 * 60 * 1000) && matches(this.lastOtpType)) {
                const otp = this.lastOtp;
                this.lastOtp = null; // consume it
                return resolve(otp);
            }

            const onOtp = (payload) => {
                // Support both the new {otp,type} shape and a bare string, for safety.
                const otp = (payload && typeof payload === 'object') ? payload.otp : payload;
                const type = (payload && typeof payload === 'object') ? payload.type : null;
                if (!matches(type)) return; // wrong channel — keep listening
                clearTimeout(timeout);
                this.otpEmitter.removeListener('otp_received', onOtp);
                resolve(otp);
            };

            const timeout = setTimeout(() => {
                this.otpEmitter.removeListener('otp_received', onOtp);
                reject(new Error(`OTP timeout after ${timeoutMs}ms${wantType ? ` (waiting for ${wantType})` : ''}`));
            }, timeoutMs);

            this.otpEmitter.on('otp_received', onOtp);
        });
    }

    disconnect() {
        for (const socket of this.sockets.values()) {
            socket.disconnect();
        }
        this.sockets.clear();
        this.isConnected = false;
    }

    injectOtp(otp, type = null) {
        const t = type === 'email' ? 'email' : (type === 'sms' ? 'sms' : (this.lastOtpType || 'sms'));
        logger.info(`✍️ [${this.phoneNumber}] Manual OTP INJECTED (${t}): ${otp}`);
        this.lastOtp = otp;
        this.lastOtpTime = Date.now();
        this.lastOtpType = t;
        this.otpEmitter.emit('otp_received', { otp, type: t });
    }
}

module.exports = {
    OtpClient
};
