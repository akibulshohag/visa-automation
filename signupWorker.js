const { IvacApi } = require('./api');
const { captchaManager } = require('./captcha');
const { logger, insertLog, updateSignupStatus, saveSignupRequestId, saveSignupProgress } = require('./database');
const { pullCipherKeys } = require('./cipherKeys');

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ─── Shared "pull the latest bundle from live" gate ────────────────────────────
// Starting a whole list of signups shouldn't re-download the site bundle once per row. The first
// worker to ask triggers a single pull; everyone started within the same window reuses its result.
let _bundlePull = { promise: null, at: 0 };
const BUNDLE_REUSE_MS = 60 * 1000;

async function pullBundleOnce(onProgress) {
    const fresh = _bundlePull.promise && (Date.now() - _bundlePull.at < BUNDLE_REUSE_MS);
    if (!fresh) {
        _bundlePull = {
            at: Date.now(),
            promise: pullCipherKeys((msg) => { logger.info(`[Signup/Cipher] ${msg}`); if (onProgress) onProgress(msg); })
                .catch(e => { _bundlePull.promise = null; throw e; }),
        };
    }
    return _bundlePull.promise;
}

/**
 * Drives one queued signup row through the live IVAC registration flow:
 *   pull bundle → phone Turnstile + signupOtp(PHONE) → phone OTP verify
 *              → email Turnstile + signupOtp(EMAIL) → email OTP verify
 *              → /auth/signup (full profile + password + consent).
 * Both OTPs arrive on the same otps.top socket (subscribed by phone) and are told apart by the
 * relay's mail.type ('email' vs sms) — see otpListener.OtpClient.waitForOtp(timeout, wantType).
 */
class SignupWorker {
    constructor(signup, proxies, config = {}, io = null, otpClient = null, opts = {}) {
        this.signup = signup;
        this.proxies = proxies || [];
        this.io = io;
        this.otpClient = otpClient;
        this.rawConfig = config;
        // Only the endpoint/captcha/pacing keys the API layer needs, mirroring BotWorker.
        this.config = {
            ep_signup_url: config.ep_signup_url,
            ep_signup_captchaType: config.ep_signup_captchaType,
            ep_signup_siteKey: config.ep_signup_siteKey,
            ep_signup_ip_count: parseInt(config.ep_signup_ip_count || 1),
            api_timeout: parseInt(config.api_timeout || 30),
            cfMinIntervalMs: parseInt(config.cf_min_interval_ms || 700),
            cfBackoffBase: parseInt(config.cf_backoff_base_ms || 2000),
            cfBackoffMax: parseInt(config.cf_backoff_max_ms || 45000),
            cfCacheBuster: parseInt(config.cf_cache_buster || 0),
        };
        this.otpTimeoutMs = parseInt(opts.otpTimeoutMs || 5 * 60 * 1000);
        this.refreshBundle = opts.refreshBundle !== false; // default: pull the bundle before signing up
        this.retryDelay = parseInt(config.retryDelay || 5) * 1000;
        this.submitRetries = parseInt(opts.submitRetries || 4);

        // Resume support. step: 0=nothing, 1=phone verified, 2=email verified, 3=done. A caller can
        // force a starting point with opts.fromStep (e.g. 0 to restart from scratch); otherwise we
        // pick up from whatever was persisted on the row. `progress` carries the OTPs/tokens captured
        // on earlier steps so a resumed /auth/signup can still echo them.
        // 5-step model matching the UI selector:
        //   1 Mobile check (send phone OTP)   2 Mobile OTP verify
        //   3 Email check (send email OTP)    4 Email OTP verify   5 Sign up (submit)
        // signup.step = number of COMPLETED steps (0..5). this.startStep = the first step to run
        // (1..5). opts.fromStep (from the UI dropdown / Restart) selects the start directly; when
        // omitted we resume from the row's saved step (Continue). Starting at step 1 = full restart,
        // which discards any OTPs/tokens captured on a previous run.
        let fs = (opts.fromStep !== undefined && opts.fromStep !== null)
            ? parseInt(opts.fromStep)
            : parseInt(signup.step || 0) + 1;
        if (isNaN(fs) || fs < 1) fs = 1;
        if (fs > 5) fs = 5;
        this.startStep = fs;
        this.progress = {};
        if (signup.progress) {
            try { this.progress = JSON.parse(signup.progress) || {}; } catch (e) { this.progress = {}; }
        }
        if (this.startStep <= 1) this.progress = {}; // restart from the top discards stale OTPs/tokens

        const initialProxy = this.proxies.length ? this.proxies[0].proxy_url : null;
        this.api = new IvacApi(initialProxy, this.config, null);
        this.api.setProxyPool(this.proxies.map(p => p.proxy_url));
        this.api.onLog = (level, msg) => this.log(level, msg);

        this.isRunning = true;
        this.abort = new AbortController();
    }

    log(level, message) {
        const time = new Date().toISOString();
        (logger[level] || logger.info)(`[signup:${this.signup.phone}] ${message}`);
        insertLog(this.signup.phone, level.toUpperCase(), message);
        if (this.io) this.io.emit('signup_log', { id: this.signup.id, phone: this.signup.phone, level: level.toUpperCase(), message, time });
    }

    setStatus(status, lastLog = null) {
        updateSignupStatus(this.signup.id, status, lastLog).catch(() => { });
        if (this.io) this.io.emit('signup_status', { id: this.signup.id, phone: this.signup.phone, status, lastLog, time: new Date().toISOString() });
    }

    stop() {
        this.isRunning = false;
        try { this.abort.abort(); } catch (e) { }
        this.log('warn', 'Signup stopped by user.');
    }

    _proxyUrl() {
        return this.proxies.length ? this.proxies[0].proxy_url : null;
    }

    // Pull one Turnstile token for the signup site key (raw x-token, like the file-upload step).
    async _getTurnstileToken() {
        const solver = captchaManager.getSolver(`signup_${this.signup.id}`, this._proxyUrl(), this.config.ep_signup_captchaType, this.config.ep_signup_siteKey);
        for (let i = 0; i < 30 && this.isRunning; i++) {
            const r = await solver.getToken();
            if (r && r.token) return r.token;
            await sleep(1000);
        }
        return null;
    }

    // Dig a requestId out of whatever envelope the API returns ({data:{requestId}} / {requestId}).
    _extractRequestId(resp) {
        const d = resp && resp.data;
        if (!d) return null;
        return (d.data && (d.data.requestId || d.data.request_id)) || d.requestId || d.request_id || null;
    }

    _isSuccess(resp) {
        if (!resp || !resp.ok) return false;
        const d = resp.data;
        // Treat an explicit success:false / status:'error' payload as a failure even on HTTP 200.
        if (d && typeof d === 'object') {
            if (d.success === false) return false;
            if (typeof d.status === 'string' && d.status.toLowerCase() === 'error') return false;
        }
        return true;
    }

    _errText(resp) {
        const d = resp && resp.data;
        if (d && typeof d === 'object') return d.message || d.error || (d.data && d.data.message) || JSON.stringify(d).slice(0, 300);
        if (typeof d === 'string') return d.slice(0, 300);
        return `HTTP ${resp ? resp.status : '??'}`;
    }

    // "Check" half of a channel: solve Turnstile → request the OTP → capture requestId + token into
    // this.progress (so a later verify can use the requestId and /auth/signup can echo the token).
    // channel: 'PHONE' | 'EMAIL'.
    async _sendOtp(channel) {
        const isEmail = channel === 'EMAIL';
        const identifier = isEmail ? this.signup.email : this.signup.phone;
        const label = isEmail ? 'Email' : 'Phone';

        this.log('info', `🔐 ${label} check: solving Turnstile...`);
        const token = await this._getTurnstileToken();
        if (!token) throw new Error(`${label} Turnstile token unavailable`);
        if (!this.isRunning) throw new Error('stopped');

        this.log('info', `📨 ${label} check: requesting OTP for ${identifier}...`);
        const sendResp = await this.api.sendSignupOtp(channel, identifier, token, this.abort);
        if (!this._isSuccess(sendResp)) throw new Error(`${label} OTP request failed: ${this._errText(sendResp)}`);
        const requestId = this._extractRequestId(sendResp) || this.signup.request_id || null;
        if (requestId) { this.api.setRequestId(requestId); saveSignupRequestId(this.signup.id, requestId).catch(() => { }); }
        this.log('info', `📨 ${label} check: OTP requested (requestId: ${requestId || 'n/a'}).`);

        if (isEmail) { this.progress.emailToken = token; this.progress.emailRequestId = requestId; }
        else { this.progress.phoneToken = token; this.progress.phoneRequestId = requestId; }
    }

    // "OTP verify" half of a channel: wait for the matching OTP on the shared socket → verify it with
    // the stored requestId. Uses a requestId captured by _sendOtp this run, or one persisted earlier
    // (resume). channel: 'PHONE' | 'EMAIL'.
    async _verifyOtp(channel) {
        const isEmail = channel === 'EMAIL';
        const identifier = isEmail ? this.signup.email : this.signup.phone;
        const wantType = isEmail ? 'email' : 'sms';
        const label = isEmail ? 'Email' : 'Phone';
        const requestId = (isEmail ? this.progress.emailRequestId : this.progress.phoneRequestId) || this.signup.request_id || null;
        if (requestId) this.api.setRequestId(requestId);

        this.log('info', `⏳ ${label} verify: waiting for OTP…`);
        let code;
        try {
            code = await this.otpClient.waitForOtp(this.otpTimeoutMs, wantType);
        } catch (e) {
            throw new Error(`${label} OTP not received: ${e.message}`);
        }
        if (!this.isRunning) throw new Error('stopped');
        this.log('info', `📲 ${label} verify: OTP received (${code}) — verifying...`);

        const verifyResp = await this.api.verifySignupOtp(channel, identifier, code, requestId, this.abort);
        if (!this._isSuccess(verifyResp)) throw new Error(`${label} OTP verify failed: ${this._errText(verifyResp)}`);
        this.log('info', `✅ ${label} verified.`);
        if (isEmail) this.progress.emailOtp = code; else this.progress.phoneOtp = code;
    }

    // Build the /auth/signup payload from the queued row + the verified OTPs/tokens (from this.progress,
    // which is populated live this run or reloaded from a resumed row). Field names mirror the live
    // site's signup form state (verified in the site bundle). The exact body is logged (minus password)
    // on every run so it can be reconciled against the live site.
    _buildSignupPayload() {
        const p = this.progress || {};
        return {
            email: this.signup.email,
            givenName: this.signup.given_name || '',
            surname: this.signup.surname || '',
            dateOfBirth: this.signup.dob || '',
            nid: this.signup.nid || null,
            passport: this.signup.passport || '',
            phone: this.signup.phone,
            password: this.signup.password,
            confirmPassword: this.signup.password,
            consent: true,
            isEmailVerified: true,
            phoneOTP: p.phoneOtp || '',
            emailOTP: p.emailOtp || '',
            phoneTurnstileToken: p.phoneToken || '',
            emailTurnstileToken: p.emailToken || '',
        };
    }

    // Persist how far we got (step + captured OTPs/tokens) and mirror it to the dashboard, so a later
    // Continue/Retry resumes from here instead of starting over.
    async _persist(step, status, lastLog = null) {
        this.signup.step = step;
        try { await saveSignupProgress(this.signup.id, step, status, this.progress); } catch (e) { }
        if (lastLog !== null) { try { await updateSignupStatus(this.signup.id, status, lastLog); } catch (e) { } }
        if (this.io) this.io.emit('signup_status', { id: this.signup.id, phone: this.signup.phone, status, step, lastLog, time: new Date().toISOString() });
    }

    async _submitWithRetry() {
        const RETRYABLE = new Set([0, 408, 409, 419, 425, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524, 525]);
        const payload = this._buildSignupPayload();
        const { password, confirmPassword, ...loggable } = payload;
        this.log('info', `📝 Submitting /auth/signup: ${JSON.stringify(loggable)}`);
        let attempt = 0;
        while (this.isRunning) {
            const resp = await this.api.submitSignup(payload, this.abort);
            if (this._isSuccess(resp)) return resp;
            const status = resp ? resp.status : 0;
            attempt++;
            if (!RETRYABLE.has(status) || attempt > this.submitRetries) {
                throw new Error(`Signup submit failed: ${this._errText(resp)}`);
            }
            this.log('warn', `Signup submit attempt ${attempt}/${this.submitRetries} failed (${status}) — retrying in ${this.retryDelay / 1000}s…`);
            await sleep(this.retryDelay);
        }
        throw new Error('stopped');
    }

    async run() {
        try {
            const resuming = this.startStep > 0;
            this.setStatus('RUNNING', resuming ? `Resuming from step ${this.startStep}…` : 'Starting…');
            this.log('info', `🚀 Signup ${resuming ? 'resumed' : 'started'} for ${this.signup.phone} / ${this.signup.email} (from step ${this.startStep})`);

            if (this.refreshBundle) {
                this.log('info', '⬇️  Pulling latest bundle from live…');
                try {
                    const info = await pullBundleOnce((msg) => this.log('info', `cipher: ${msg}`));
                    this.log('info', `🔐 Bundle updated (version ${info && info.version !== undefined ? info.version : '?'}).`);
                } catch (e) {
                    // Non-fatal: the signup calls may still work with the cached bundle.
                    this.log('warn', `Bundle pull failed (${e.message}) — continuing with cached cipher.`);
                }
            }
            if (!this.isRunning) return;

            // Make sure the socket is subscribed to this phone before any OTP is triggered.
            if (this.otpClient && !this.otpClient.isConnected) this.otpClient.connect();

            // Five steps; each runs only when we're starting at or before it. A resumed run enters
            // partway (e.g. startStep=4 → jump straight to the email OTP verify).
            // Step 1 — Mobile check (send phone OTP)
            if (this.startStep <= 1) {
                await this._sendOtp('PHONE');
                if (!this.isRunning) return;
                await this._persist(1, 'PHONE_OTP_SENT', 'Phone OTP sent');
            }
            // Step 2 — Mobile OTP verify
            if (this.startStep <= 2) {
                await this._verifyOtp('PHONE');
                if (!this.isRunning) return;
                await this._persist(2, 'PHONE_VERIFIED', 'Phone verified');
            }
            // Step 3 — Email check (send email OTP)
            if (this.startStep <= 3) {
                await this._sendOtp('EMAIL');
                if (!this.isRunning) return;
                await this._persist(3, 'EMAIL_OTP_SENT', 'Email OTP sent');
            }
            // Step 4 — Email OTP verify
            if (this.startStep <= 4) {
                await this._verifyOtp('EMAIL');
                if (!this.isRunning) return;
                await this._persist(4, 'EMAIL_VERIFIED', 'Email verified');
            }
            // Step 5 — Sign up (create the account; retries transient failures).
            await this._submitWithRetry();
            if (!this.isRunning) return;
            await this._persist(5, 'DONE', 'Signup completed');
            this.log('info', '🎉 Signup completed successfully.');
        } catch (e) {
            if (!this.isRunning && /stopped|abort/i.test(e.message || '')) {
                this.setStatus('STOPPED', 'Stopped');
            } else {
                // Keep step/progress so the user can edit + Continue from the last good point.
                this.log('error', `❌ Signup failed: ${e.message}`);
                this.setStatus('FAILED', e.message);
            }
        } finally {
            this.isRunning = false;
        }
    }
}

module.exports = { SignupWorker };
