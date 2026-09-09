process.env.TZ = 'Asia/Dhaka';
require('dotenv').config();

// Safety net: a long-running multi-account bot must never die from one stray async error
// (e.g. a cancelled request's CancelError). Log and keep running instead of crashing.
process.on('unhandledRejection', (reason) => {
    const msg = reason && reason.message ? reason.message : String(reason);
    try { require('./database').logger.warn(`⚠️ Unhandled rejection (ignored): ${msg}`); }
    catch (e) { console.warn('Unhandled rejection (ignored):', msg); }
});
process.on('uncaughtException', (err) => {
    const msg = err && err.message ? err.message : String(err);
    try { require('./database').logger.error(`⚠️ Uncaught exception (ignored): ${msg}`); }
    catch (e) { console.error('Uncaught exception (ignored):', msg); }
});

let _shuttingDown = false;
function gracefulShutdown(sig) {
    if (_shuttingDown) return; // ignore repeat Ctrl-C
    _shuttingDown = true;
    console.log(`\n🛑 Gracefully shutting down from ${sig}`);
    try { require('./database').logger.info(`🛑 Shutting down from ${sig}`); } catch (e) {}
    // Stop the cipher auto-pull loop and free the Go-backed httpcloak session. httpcloak
    // keeps the event loop ref'd open while a request is pending (setInterval keep-alive),
    // so a wedged QUIC pull would otherwise stop Node from exiting and leave port 3000 bound.
    try { require('./cipherKeys').closeCipherSession(); } catch (e) {}
    process.exit(0);
}
process.on('SIGINT', () => gracefulShutdown('SIGINT (Ctrl-C)'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const fs = require('fs');
const multer = require('multer');

const {
    initDb, getAccounts, getAccount, createAccount, updateAccount, deleteAccount, resetAccountStatus,
    toggleAccountActivity, addAccountFile, getAccountFiles, getAccountFile, deleteAccountFile,
    resetAccountFilesUploaded,
    getAllProxiesForAccount, addProxy, deleteProxy, updateAccountStatus,
    getAllProxies, toggleProxy, bulkDeleteProxies, reassignProxy,
    getConfig, setConfig, getProxiesForAccount, logger,
    getRecentLogs, clearLogsForAccount, cleanOldLogs, insertLog,
    getActiveApiIps, getApiIps, addApiIp, deleteApiIp, bulkDeleteApiIps, toggleApiIp,
    getActiveOtpServers, getOtpServers, addOtpServer, deleteOtpServer, toggleOtpServer,
    getCallbackTasks, addCallbackTask, deleteCallbackTask, toggleCallbackTask,
    getSignups, getSignup, createSignup, updateSignup, deleteSignup, updateSignupStatus, convertSignupToAccount
} = require('./database');
const { BotWorker } = require('./botWorker');
const { SignupWorker } = require('./signupWorker');
const { captchaManager } = require('./captcha');
const { OtpClient } = require('./otpListener');
const { loadFromDb: loadCipherKeys, pullCipherKeys, startAutoPull, stopAutoPull, getAutoPullStatus, getCachedCipherInfo, testEncrypt, testDecrypt } = require('./cipherKeys');
const { compressPdfBytes } = require('./pdfCompressor');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Chrome auto-detection ──────────────────────────────────────────────────────
// Puppeteer normally launches the Chrome build it downloads into its cache during
// `npm install`. On a machine where that download never ran (the usual cause of the
// "Could not find Chrome (verXXX)" error when copying the project around), there is no
// browser to launch. So we auto-detect a real installed Google Chrome / Edge and point
// Puppeteer at it via executablePath, only falling back to the bundled build if found.
let _cachedChromePath; // undefined = not resolved yet, null = none found
function resolveChromePath() {
    if (_cachedChromePath !== undefined) return _cachedChromePath;
    const fs = require('fs');
    const candidates = [];
    if (process.platform === 'win32') {
        const pf = process.env['ProgramFiles'] || 'C:\\Program Files';
        const pf86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';
        const local = process.env['LOCALAPPDATA'];
        candidates.push(
            `${pf}\\Google\\Chrome\\Application\\chrome.exe`,
            `${pf86}\\Google\\Chrome\\Application\\chrome.exe`,
            local && `${local}\\Google\\Chrome\\Application\\chrome.exe`,
            // Edge is Chromium-based — a perfectly good fallback if Chrome isn't installed.
            `${pf86}\\Microsoft\\Edge\\Application\\msedge.exe`,
            `${pf}\\Microsoft\\Edge\\Application\\msedge.exe`
        );
    } else if (process.platform === 'darwin') {
        candidates.push(
            '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
            '/Applications/Google Chrome Beta.app/Contents/MacOS/Google Chrome Beta',
            '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'
        );
    } else {
        candidates.push(
            '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable',
            '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/microsoft-edge'
        );
    }
    for (const c of candidates) {
        if (c && fs.existsSync(c)) {
            _cachedChromePath = c;
            logger.info(`[Browser] Using installed browser: ${c}`);
            return _cachedChromePath;
        }
    }
    // Last resort: Puppeteer's own downloaded build, if it actually exists on disk.
    try {
        const bundled = require('puppeteer').executablePath();
        if (bundled && fs.existsSync(bundled)) {
            _cachedChromePath = bundled;
            logger.info(`[Browser] Using Puppeteer's bundled Chromium: ${bundled}`);
            return _cachedChromePath;
        }
    } catch (e) { /* puppeteer couldn't resolve a path */ }
    _cachedChromePath = null;
    logger.warn('[Browser] No installed Chrome/Edge found and no bundled Chromium — browser launches will fail. Install Google Chrome.');
    return _cachedChromePath;
}

// Chrome resolver for the CAPTCHA SOLVER specifically. Cloudflare Turnstile scores the
// bundled Chrome-for-Testing build noticeably better than a real auto-updating Chrome
// install (real Chrome started failing with "Verification failed" after we switched the
// solver onto resolveChromePath()). So here we PREFER Puppeteer's bundled build and only
// fall back to an installed Chrome/Edge if the bundle isn't on disk.
let _cachedSolverChromePath;
function resolveSolverChromePath() {
    if (_cachedSolverChromePath !== undefined) return _cachedSolverChromePath;
    const fs = require('fs');
    try {
        const bundled = require('puppeteer').executablePath();
        if (bundled && fs.existsSync(bundled)) {
            _cachedSolverChromePath = bundled;
            logger.info(`[Solver] Using Puppeteer's bundled Chrome-for-Testing: ${bundled}`);
            return _cachedSolverChromePath;
        }
    } catch (e) { /* fall through to installed Chrome */ }
    _cachedSolverChromePath = resolveChromePath();
    logger.warn('[Solver] Bundled Chrome-for-Testing not found — falling back to installed Chrome (Turnstile may score worse).');
    return _cachedSolverChromePath;
}

// Detects the PRIMARY monitor's full bounds so per-account browser windows can be tiled to fit
// any monitor instead of a hardcoded 1920×1080 grid. We use the full Bounds (not WorkingArea):
// window TITLE BARS sit at the top, so letting the bottom row reach a few px behind the taskbar
// keeps every window fully clickable while preserving the familiar 3×2 grid on a 1080p screen.
// On Windows we shell out once to PowerShell; the result is cached so we never re-shell per
// request. Anywhere else, or on any failure, we fall back to a safe 1920×1080.
let _cachedScreenSize;
function getScreenSize() {
    if (_cachedScreenSize !== undefined) return _cachedScreenSize;
    const fallback = { width: 1920, height: 1080 };
    if (process.platform === 'win32') {
        try {
            const { execSync } = require('child_process');
            const out = execSync(
                'powershell -NoProfile -Command "Add-Type -AssemblyName System.Windows.Forms; $b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds; \\"$($b.Width)x$($b.Height)\\""',
                { encoding: 'utf8', timeout: 5000 }
            ).trim();
            const m = out.match(/^(\d+)x(\d+)$/);
            if (m) {
                _cachedScreenSize = { width: parseInt(m[1], 10), height: parseInt(m[2], 10) };
                logger.info(`[Browser] Detected screen size: ${_cachedScreenSize.width}x${_cachedScreenSize.height}`);
                return _cachedScreenSize;
            }
            logger.warn(`[Browser] Could not parse screen size "${out}" — using ${fallback.width}x${fallback.height}.`);
        } catch (e) {
            logger.warn(`[Browser] Screen-size detection failed (${e.message}) — using ${fallback.width}x${fallback.height}.`);
        }
    } else {
        logger.warn(`[Browser] Screen-size detection only supported on Windows — using ${fallback.width}x${fallback.height}.`);
    }
    _cachedScreenSize = fallback;
    return _cachedScreenSize;
}

// ─── Bot State ────────────────────────────────────────────────────────────────
let activeWorkers = {};  // phone => BotWorker
let activeSignupWorkers = {}; // signup id => SignupWorker
let globalOtpClients = {}; // phone => persistent OtpClient
let activeOtpServers = []; // cached list of active OTP server URLs (all accounts connect to all)
let autoStartTimer = null;
let captchaWarmTimer = null;
let autoStartOtpTimeout = 30;

// ─── Callback Manager ─────────────────────────────────────────────────────────
const callbackManager = {
    activeTasks: {}, // id -> state
    async startTask(task) {
        if (this.activeTasks[task.id]) return; // already running
        logger.info(`Starting callback task ${task.id} with ${task.workers} workers`);
        this.activeTasks[task.id] = { timers: [], isRunning: true };

        let gotScrapingFn = null;
        try {
            const mod = await import('got-scraping');
            gotScrapingFn = mod.gotScraping;
        } catch (e) {
            logger.error('Failed to load got-scraping for callback tasks');
            return;
        }

        const http = require('http');
        const https = require('https');
        const { randomUUID } = require('crypto');
        const keepAliveAgent = {
            http: new http.Agent({ keepAlive: true, keepAliveMsecs: 30000, maxSockets: 512, maxFreeSockets: 64 }),
            https: new https.Agent({ keepAlive: true, keepAliveMsecs: 30000, maxSockets: 512, maxFreeSockets: 64, rejectUnauthorized: false })
        };

        for (let i = 0; i < task.workers; i++) {
            const runLoop = async () => {
                if (!this.activeTasks[task.id] || !this.activeTasks[task.id].isRunning) return; // stopped

                try {
                    let targetUrl = task.uri;
                    const urlObj = new URL(targetUrl);
                    let isOriginBypass = false;
                    let originalHost = urlObj.hostname;

                    const ips = await getActiveApiIps();
                    if (originalHost === 'api.ivacbd.com' && ips && ips.length > 0) {
                        const randomIp = ips[Math.floor(Math.random() * ips.length)];
                        urlObj.hostname = randomIp;
                        targetUrl = urlObj.toString();
                        isOriginBypass = true;
                    }

                    const _t = Date.now();
                    const _r = randomUUID();
                    const separator = targetUrl.includes('?') ? '&' : '?';
                    targetUrl = `${targetUrl}${separator}_t=${_t}&_r=${_r}`;

                    const options = {
                        method: 'GET',
                        headers: {
                            'accept': 'application/json, text/plain, */*',
                            'accept-language': 'en-US,en;q=0.9',
                            'origin': 'https://appointment.ivacbd.com',
                            'referer': 'https://appointment.ivacbd.com/',
                            'cache-control': 'no-cache, no-store, must-revalidate',
                            'pragma': 'no-cache',
                            'expires': '0'
                        },
                        retry: { limit: 0 },
                        throwHttpErrors: false,
                        http2: !isOriginBypass,
                        agent: keepAliveAgent,
                        timeout: { request: 15000 },
                        headerGeneratorOptions: {
                            browsers: [{ name: 'chrome', minVersion: 115, maxVersion: 124 }],
                            devices: ['desktop'],
                            locales: ['en-US', 'en'],
                            os: ['windows']
                        }
                    };

                    if (isOriginBypass) {
                        options.headers['Host'] = originalHost;
                        options.https = { rejectUnauthorized: false };
                    }

                    const response = await gotScrapingFn(targetUrl, options);
                    const status = response.statusCode;
                    const ok = status >= 200 && status < 300;
                    const timeStr = new Date().toISOString().split('T')[1].split('Z')[0];
                    const logEntry = `[${timeStr}] [Task ${task.id}] W${i + 1} ${ok ? '✅' : '❌'} ${status} via ${urlObj.hostname}`;
                    io.emit('callback_log', { id: task.id, message: logEntry, isError: !ok });
                } catch (e) {
                    const timeStr = new Date().toISOString().split('T')[1].split('Z')[0];
                    const logEntry = `[${timeStr}] [Task ${task.id}] W${i + 1} ❌ Error: ${e.message}`;
                    io.emit('callback_log', { id: task.id, message: logEntry, isError: true });
                }

                if (this.activeTasks[task.id] && this.activeTasks[task.id].isRunning) {
                    const timer = setTimeout(runLoop, task.interval_ms);
                    this.activeTasks[task.id].timers.push(timer);
                }
            };

            // Initial slight offset to prevent all workers firing at exact same MS
            setTimeout(runLoop, i * 50);
        }
    },
    stopTask(id) {
        if (this.activeTasks[id]) {
            logger.info(`Stopping callback task ${id}`);
            this.activeTasks[id].isRunning = false;
            for (const timer of this.activeTasks[id].timers) {
                clearTimeout(timer);
            }
            delete this.activeTasks[id];
        }
    }
};

// Initialize persistent OTP connection for a phone
function ensureOtpClient(phone) {
    if (!globalOtpClients[phone]) {
        globalOtpClients[phone] = new OtpClient(phone, activeOtpServers);
        globalOtpClients[phone].otpEmitter.on('otp_received', (payload) => {
            // Payload is now { otp, type } ('email' | 'sms'); tolerate a bare string for safety.
            const otp = (payload && typeof payload === 'object') ? payload.otp : payload;
            const type = (payload && typeof payload === 'object') ? payload.type : null;
            const icon = type === 'email' ? '📧' : '📱';
            const msg = `${icon} Last OTP received${type ? ` (${type})` : ''}: ${otp}`;
            insertLog(phone, 'INFO', msg);
            io.emit('account_log', { phone, level: 'INFO', message: msg, time: new Date().toISOString() });
            io.emit('last_otp_updated', { phone, otp, type, time: new Date().toISOString() });
        });
        globalOtpClients[phone].connect();
    }
    return globalOtpClients[phone];
}

// Reload the active OTP server list and propagate it to every live client so changes
// from the Settings page take effect without a restart.
async function refreshOtpServers() {
    activeOtpServers = await getActiveOtpServers();
    for (const client of Object.values(globalOtpClients)) {
        client.setServers(activeOtpServers);
    }
}

function broadcastState() {
    io.emit('bot_state', {
        running: Object.keys(activeWorkers),
        autoStart: autoStartTimer !== null
    });
}

// Broadcast server time every second to sync frontend clock
setInterval(() => io.emit('server_time', Date.now()), 1000);

// ─── REST API: Accounts ───────────────────────────────────────────────────────
app.get('/api/accounts', async (req, res) => {
    try { res.json(await getAccounts()); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/accounts', async (req, res) => {
    try {
        const { phone, password, name, email, assigned_ip } = req.body;
        if (!phone || !password) return res.status(400).json({ error: 'Phone and password required' });
        await createAccount(phone, password, name || null, email || null, assigned_ip || null);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/accounts/:id', async (req, res) => {
    try {
        const { phone, password, name, email, assigned_ip } = req.body;
        if (!phone || !password) return res.status(400).json({ error: 'Phone and password required' });
        await updateAccount(req.params.id, phone, password, name || null, email || null, assigned_ip || null);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/accounts/:id', async (req, res) => {
    try {
        await deleteAccount(req.params.id);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/accounts/:id/reset', async (req, res) => {
    try {
        await resetAccountStatus(req.params.id);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── REST API: Account files (PDFs for the file-upload step) ───────────────────
const UPLOAD_ROOT = path.join(__dirname, 'uploads');
const fileUpload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            const dir = path.join(UPLOAD_ROOT, String(req.params.id));
            fs.mkdirSync(dir, { recursive: true });
            cb(null, dir);
        },
        filename: (req, file, cb) => {
            const { randomUUID } = require('crypto');
            cb(null, `${randomUUID()}.pdf`);
        }
    }),
    limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB — matches the IVAC site's own limit
    fileFilter: (req, file, cb) => {
        const isPdf = file.mimetype === 'application/pdf' || file.originalname.toLowerCase().endsWith('.pdf');
        cb(isPdf ? null : new Error('Only PDF files are allowed'), isPdf);
    }
});

app.get('/api/accounts/:id/files', async (req, res) => {
    try { res.json(await getAccountFiles(req.params.id)); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/accounts/:id/files', (req, res) => {
    fileUpload.array('files')(req, res, async (err) => {
        if (err) return res.status(400).json({ error: err.message });
        try {
            const existing = await getAccountFiles(req.params.id);
            let nextIndex = existing.length;
            for (const file of (req.files || [])) {
                // Compress the uploaded PDF in place to the target size window. If anything
                // goes wrong, keep the original file so an upload is never lost.
                let byteSize = file.size;
                try {
                    const original = fs.readFileSync(file.path);
                    const compressed = Buffer.from(await compressPdfBytes(original));
                    fs.writeFileSync(file.path, compressed);
                    byteSize = compressed.length;
                    logger.info(`📄 Compressed "${file.originalname}" ${(file.size / 1024).toFixed(1)}KB -> ${(byteSize / 1024).toFixed(1)}KB`);
                } catch (compressErr) {
                    logger.warn(`⚠️ PDF compression failed for "${file.originalname}" (${compressErr.message}) — keeping original`);
                }
                await addAccountFile(req.params.id, {
                    filename: file.originalname,
                    mime: file.mimetype,
                    byteSize,
                    applicantIndex: nextIndex,
                    isPrimary: nextIndex === 0,
                    webFileNumber: req.body.webFileNumber || null,
                    storagePath: file.path
                });
                nextIndex++;
            }
            res.json({ success: true, count: (req.files || []).length });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });
});

app.delete('/api/accounts/:id/files/:fileId', async (req, res) => {
    try {
        const file = await getAccountFile(req.params.fileId);
        if (file && file.storage_path) {
            try { fs.unlinkSync(file.storage_path); } catch (e) { /* already gone */ }
        }
        await deleteAccountFile(req.params.fileId);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Clear the uploaded flag on all of an account's files so the next run re-uploads them.
app.post('/api/accounts/:id/files/reset-uploads', async (req, res) => {
    try {
        await resetAccountFilesUploaded(req.params.id);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/accounts/:id/toggle', async (req, res) => {
    try {
        const { isActive } = req.body;
        await toggleAccountActivity(req.params.id, isActive);
        const account = await getAccount(req.params.id);
        if (account) {
            io.emit('account_updated', account);
        }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── REST API: Proxies ────────────────────────────────────────────────────────
app.get('/api/accounts/:id/proxies', async (req, res) => {
    try { res.json(await getAllProxiesForAccount(req.params.id)); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/accounts/:id/proxies', async (req, res) => {
    try {
        const { proxy_url } = req.body;
        if (!proxy_url) return res.status(400).json({ error: 'proxy_url required' });
        const id = await addProxy(req.params.id, proxy_url);
        res.json({ id, proxy_url, is_active: 1 });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/accounts/:id/proxies/bulk', async (req, res) => {
    try {
        const { proxies } = req.body;
        if (!Array.isArray(proxies)) return res.status(400).json({ error: 'proxies array required' });
        const ids = [];
        for (const proxy_url of proxies) {
            if (proxy_url.trim()) ids.push(await addProxy(req.params.id, proxy_url.trim()));
        }
        res.json({ created: ids.length });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/proxies/:id', async (req, res) => {
    try {
        await deleteProxy(req.params.id);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── REST API: Global Proxy Manager ───────────────────────────────────────────
app.get('/api/proxies', async (req, res) => {
    try { res.json(await getAllProxies()); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/proxies/bulk-delete', async (req, res) => {
    try {
        const { ids } = req.body;
        if (!Array.isArray(ids)) return res.status(400).json({ error: 'ids array required' });
        await bulkDeleteProxies(ids);
        res.json({ success: true, deleted: ids.length });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/proxies/:id/toggle', async (req, res) => {
    try {
        const { isActive } = req.body;
        await toggleProxy(req.params.id, isActive);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/proxies/:id/reassign', async (req, res) => {
    try {
        const { account_id } = req.body;
        if (!account_id) return res.status(400).json({ error: 'account_id required' });
        await reassignProxy(req.params.id, account_id);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Reusable proxy connectivity check — fetches Cloudflare's trace endpoint through the proxy and
// reports the exit IP, ping, proxy type and negotiated protocol. Mirrors the per-account CP check.
async function runProxyCheck(rawProxyUrl) {
    const { formatProxyUrl, friendlyProtocol } = require('./api');
    const formattedProxy = formatProxyUrl(rawProxyUrl);
    if (!formattedProxy) return { success: false, error: 'Invalid or empty proxy' };
    const proxyType = formattedProxy.startsWith('socks5') ? 'SOCKS5' : 'HTTP';
    // Match the bot's logic: HTTP/3 for SOCKS5, HTTP/2 for HTTP proxies.
    const httpVersionToUse = proxyType === 'SOCKS5' ? 'h3' : 'h2';
    const startTime = Date.now();
    const httpcloak = require('httpcloak');
    let session = null;
    try {
        session = new httpcloak.Session({ preset: 'chrome-116-windows', proxy: formattedProxy, httpVersion: httpVersionToUse, timeout: 10 });
        const response = await session.request('GET', 'https://cloudflare.com/cdn-cgi/trace', { headers: { 'accept': '*/*' } });
        if (response.statusCode >= 200 && response.statusCode < 300) {
            const text = response.text || '';
            const ip = ((text.match(/ip=([^\n]+)/) || [])[1] || 'Unknown').trim();
            const cfHttp = ((text.match(/http=([^\n]+)/) || [])[1] || '').trim().toUpperCase();
            const actualProto = friendlyProtocol(response.protocol);
            const displayProto = cfHttp ? `${actualProto} (Verified by Cloudflare as ${cfHttp})` : actualProto;
            return { success: true, ip, time: Date.now() - startTime, type: proxyType, protocol: displayProto };
        }
        return { success: false, error: `HTTP ${response.statusCode}`, time: Date.now() - startTime };
    } catch (err) {
        return { success: false, error: err.message || 'Connection failed', time: Date.now() - startTime };
    } finally {
        if (session) { try { session.close(); } catch (e) { /* ignore */ } }
    }
}

app.post('/api/proxies/:id/check', async (req, res) => {
    try {
        const { proxy_url } = req.body;
        if (!proxy_url) return res.status(400).json({ error: 'proxy_url required' });
        res.json(await runProxyCheck(proxy_url));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── REST API: Log History ────────────────────────────────────────────────────
app.get('/api/accounts/:id/logs', async (req, res) => {
    try {
        const account = await getAccount(req.params.id);
        if (!account) return res.status(404).json({ error: 'Not found' });
        const limit = parseInt(req.query.limit || 300);
        const logs = await getRecentLogs(account.phone, limit);
        res.json(logs);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/accounts/:id/logs', async (req, res) => {
    try {
        const account = await getAccount(req.params.id);
        if (!account) return res.status(404).json({ error: 'Not found' });
        await clearLogsForAccount(account.phone);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── REST API: API IPs ────────────────────────────────────────────────────────
app.get('/api/ips', async (req, res) => {
    try { res.json(await getApiIps()); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/ips', async (req, res) => {
    try {
        const { ip } = req.body;
        if (!ip) return res.status(400).json({ error: 'IP required' });
        const id = await addApiIp(ip.trim());
        res.json({ id, ip: ip.trim(), is_active: 1 });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/ips/bulk', async (req, res) => {
    try {
        const { ips } = req.body;
        if (!Array.isArray(ips)) return res.status(400).json({ error: 'ips array required' });
        let added = 0;
        for (const ip of ips) {
            if (ip.trim()) {
                await addApiIp(ip.trim());
                added++;
            }
        }
        res.json({ created: added });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/ips/:id', async (req, res) => {
    try {
        await deleteApiIp(req.params.id);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/ips/bulk-delete', async (req, res) => {
    try {
        const { ids } = req.body;
        if (!Array.isArray(ids)) return res.status(400).json({ error: 'ids array required' });
        await bulkDeleteApiIps(ids);
        res.json({ success: true, deleted: ids.length });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/ips/:id/toggle', async (req, res) => {
    try {
        const { isActive } = req.body;
        await toggleApiIp(req.params.id, isActive);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── REST API: OTP Servers ────────────────────────────────────────────────────
app.get('/api/otp-servers', async (req, res) => {
    try { res.json(await getOtpServers()); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/otp-servers', async (req, res) => {
    try {
        const { url } = req.body;
        if (!url || !url.trim()) return res.status(400).json({ error: 'URL required' });
        const id = await addOtpServer(url.trim());
        await refreshOtpServers();
        res.json({ id, url: url.trim(), is_active: 1 });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/otp-servers/:id', async (req, res) => {
    try {
        await deleteOtpServer(req.params.id);
        await refreshOtpServers();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/otp-servers/:id/toggle', async (req, res) => {
    try {
        const { isActive } = req.body;
        await toggleOtpServer(req.params.id, isActive);
        await refreshOtpServers();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/ips/test', async (req, res) => {
    try {
        const { ip } = req.body;
        if (!ip) return res.status(400).json({ error: 'ip required' });

        const { gotScraping } = await import('got-scraping');
        const https = require('https');
        const agent = new https.Agent({ rejectUnauthorized: false });

        const url = `https://${ip}/iams/api/v1/auth/sign-in-v2`;
        const options = {
            method: 'GET',
            headers: {
                'Host': 'api.ivacbd.com',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
            },
            agent: { https: agent },
            timeout: { request: 8000 },
            throwHttpErrors: false,
            retry: { limit: 0 }
        };

        const response = await gotScraping(url, options);
        let statusText = 'Dead';
        if (response.statusCode === 500) statusText = 'Alive';
        else if (response.statusCode === 503) statusText = 'Alive but Server Off';
        else if (response.statusCode >= 200 && response.statusCode < 500 && response.statusCode !== 403 && response.statusCode !== 404) statusText = 'Alive (Unexpected)';

        res.json({ success: true, statusCode: response.statusCode, statusText });
    } catch (e) {
        res.json({ success: true, statusCode: 0, statusText: 'Dead (Error)' });
    }
});

// ─── REST API: Callback Tasks ─────────────────────────────────────────────────
app.get('/api/callbacks', async (req, res) => {
    try { res.json(await getCallbackTasks()); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/callbacks', async (req, res) => {
    try {
        const { uri, interval_ms, workers } = req.body;
        if (!uri) return res.status(400).json({ error: 'URI required' });
        const id = await addCallbackTask(uri.trim(), interval_ms || 1000, workers || 1);
        res.json({ id, uri, interval_ms, workers, is_active: 0 });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/callbacks/:id', async (req, res) => {
    try {
        const id = req.params.id;
        callbackManager.stopTask(id);
        await deleteCallbackTask(id);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/callbacks/:id/toggle', async (req, res) => {
    try {
        const id = req.params.id;
        const { isActive } = req.body;
        await toggleCallbackTask(id, isActive);

        if (isActive) {
            // we need the full task info to start it
            const tasks = await getCallbackTasks();
            const task = tasks.find(t => t.id == id);
            if (task) callbackManager.startTask(task);
        } else {
            callbackManager.stopTask(id);
        }

        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── REST API: Config ─────────────────────────────────────────────────────────
app.get('/api/config', async (req, res) => {
    try { res.json(await getConfig()); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/config', async (req, res) => {
    try {
        for (const [key, value] of Object.entries(req.body)) {
            await setConfig(key, String(value));
        }

        // Push config to active workers
        const newConfig = await getConfig();
        for (const worker of Object.values(activeWorkers)) {
            if (typeof worker.updateConfig === 'function') {
                worker.updateConfig(newConfig);
            }
        }

        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── Helper: launch a single account worker ───────────────────────────────────
async function launchWorker(account, config, startStep = 0, otpTimeout = 30) {
    // If an old worker exists, stop it cleanly before starting a new one
    if (activeWorkers[account.phone]) {
        logger.warn(`[${account.phone}] Existing worker found — stopping it before re-launch.`);
        activeWorkers[account.phone].stop();
        delete activeWorkers[account.phone];
        // Clear the old token timer on the dashboard
        io.emit('token_cleared', { phone: account.phone });
        // Brief pause to allow the old worker to finish its current in-flight request
        await new Promise(r => setTimeout(r, 500));
    }
    const proxies = await getProxiesForAccount(account.id);
    const otpClient = ensureOtpClient(account.phone);
    const worker = new BotWorker(account, proxies, config, io, startStep, otpTimeout, otpClient);
    activeWorkers[account.phone] = worker;
    broadcastState();
    worker.run().finally(() => {
        if (activeWorkers[account.phone] === worker) {
            delete activeWorkers[account.phone];
            broadcastState();
        }
    });
}

// ─── REST API: Bot Control — All Accounts ─────────────────────────────────────
app.post('/api/bot/start', async (req, res) => {
    try {
        const accounts = await getAccounts();
        const active = accounts.filter(a => a.status !== 'COMPLETED' && a.is_active === 1);
        if (!active.length) return res.json({ success: false, message: 'No active runnable accounts' });
        const config = await getConfig();
        const otpTimeout = req.body.otpTimeout || 30;
        const steps = req.body.steps || {};
        for (const account of active) {
            const proxies = await getProxiesForAccount(account.id);
            const proxyUrl = proxies.length > 0 ? proxies[0].proxy_url : null;
            ['ep_signin', 'ep_reserve', 'ep_payment'].forEach(k => {
                if (!config[`${k}_siteKey`]) return; // payment captcha optional — skip when unconfigured
                captchaManager.getSolver(account.id, proxyUrl, config[`${k}_captchaType`], config[`${k}_siteKey`]).fillCaptchaPool();
            });
            const step = steps[account.phone] !== undefined ? steps[account.phone] : 0;
            await launchWorker(account, config, step, otpTimeout);
        }
        res.json({ success: true, accounts: active.length });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bot/stop', async (req, res) => {
    for (const [phone, worker] of Object.entries(activeWorkers)) {
        worker.stop();
        io.emit('token_cleared', { phone });
    }
    // Note: activeWorkers cleanup happens in launchWorker.run().finally()
    broadcastState();
    res.json({ success: true });
});

app.get('/api/bot/status', (req, res) => {
    res.json({ running: Object.keys(activeWorkers), autoStart: autoStartTimer !== null });
});

app.post('/api/bot/payment-log', async (req, res) => {
    try {
        const { phone, data } = req.body;
        if (phone && data) {
            const parsed = typeof data === 'string' ? JSON.parse(data) : data;
            const msg = `💳 Payment Selected: ${parsed.name} (${parsed.type})`;
            const { insertLog } = require('./database');
            await insertLog(phone, 'INFO', msg);
            io.emit('server_message', { type: 'info', text: `[${phone}] ${msg}` });
            io.emit('account_log', { phone, level: 'INFO', message: msg, time: new Date().toISOString() });
        }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── REST API: Signups (auto sign-up queue) ──────────────────────────────────
// Signups have no per-account proxies yet, so they share the global active-proxy pool (rotated one
// per request by the API layer). Falls back to a direct connection when no proxies are configured.
function signupProxyPool(allProxies) {
    return (allProxies || []).filter(p => p.is_active).map(p => ({ proxy_url: p.proxy_url }));
}

async function launchSignupWorker(signup, config, opts = {}) {
    if (activeSignupWorkers[signup.id]) {
        activeSignupWorkers[signup.id].stop();
        delete activeSignupWorkers[signup.id];
        await new Promise(r => setTimeout(r, 300));
    }
    const proxies = signupProxyPool(await getAllProxies());
    const otpClient = ensureOtpClient(signup.phone);
    // Prime the signup Turnstile pool so the first token is ready fast.
    if (config.ep_signup_siteKey) {
        const proxyUrl = proxies.length ? proxies[0].proxy_url : null;
        captchaManager.getSolver(`signup_${signup.id}`, proxyUrl, config.ep_signup_captchaType, config.ep_signup_siteKey).fillCaptchaPool();
    }
    const worker = new SignupWorker(signup, proxies, config, io, otpClient, opts);
    activeSignupWorkers[signup.id] = worker;
    worker.run().finally(() => {
        if (activeSignupWorkers[signup.id] === worker) delete activeSignupWorkers[signup.id];
    });
}

app.get('/api/signups', async (req, res) => {
    try {
        const rows = await getSignups();
        const running = Object.keys(activeSignupWorkers).map(Number);
        res.json(rows.map(r => ({ ...r, running: running.includes(r.id) })));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Create one or many signup rows. Body: a single {email,phone,password,...} object, or {items:[...]}.
app.post('/api/signups', async (req, res) => {
    try {
        const items = Array.isArray(req.body.items) ? req.body.items : [req.body];
        const created = [], errors = [];
        for (const it of items) {
            if (!it || !it.email || !it.phone || !it.password) {
                errors.push({ item: it, error: 'email, phone and password are required' });
                continue;
            }
            try { created.push(await createSignup(it)); }
            catch (e) { errors.push({ item: { email: it.email, phone: it.phone }, error: e.message }); }
        }
        res.json({ success: errors.length === 0, created: created.length, ids: created, errors });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/signups/:id', async (req, res) => {
    try {
        const s = await getSignup(req.params.id);
        if (!s) return res.status(404).json({ error: 'Signup not found' });
        if (activeSignupWorkers[s.id]) return res.status(400).json({ error: 'Cannot edit a running signup' });
        await updateSignup(req.params.id, { ...s, ...req.body });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/signups/:id', async (req, res) => {
    try {
        if (activeSignupWorkers[req.params.id]) {
            activeSignupWorkers[req.params.id].stop();
            delete activeSignupWorkers[req.params.id];
        }
        await deleteSignup(req.params.id);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/signups/:id/start', async (req, res) => {
    try {
        const s = await getSignup(req.params.id);
        if (!s) return res.status(404).json({ error: 'Signup not found' });
        if (activeSignupWorkers[s.id]) return res.status(400).json({ error: 'Signup already running' });
        const config = await getConfig();
        const otpTimeout = req.body.otpTimeout ? parseInt(req.body.otpTimeout) * 1000 : undefined;
        // fromStep lets the UI choose Continue (omit → resume from the row's saved step) vs
        // Restart (send 0 → run the whole flow again).
        const fromStep = (req.body.fromStep !== undefined && req.body.fromStep !== null) ? parseInt(req.body.fromStep) : undefined;
        await launchSignupWorker(s, config, { otpTimeoutMs: otpTimeout, refreshBundle: req.body.refreshBundle !== false, fromStep });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Start every runnable signup (PENDING/FAILED/STOPPED, and not already running). The first worker
// pulls the bundle; the rest reuse it (see signupWorker.pullBundleOnce).
app.post('/api/signups/start-all', async (req, res) => {
    try {
        const all = await getSignups();
        const runnable = all.filter(s => !activeSignupWorkers[s.id] && !['DONE', 'CONVERTED', 'RUNNING'].includes(s.status));
        if (!runnable.length) return res.json({ success: false, message: 'No runnable signups' });
        const config = await getConfig();
        const otpTimeout = req.body.otpTimeout ? parseInt(req.body.otpTimeout) * 1000 : undefined;
        // Optional global start step (1..5). Omitted → each row resumes from its own saved step.
        const fromStep = (req.body.fromStep !== undefined && req.body.fromStep !== null && req.body.fromStep !== '')
            ? parseInt(req.body.fromStep) : undefined;
        for (const s of runnable) {
            await launchSignupWorker(s, config, { otpTimeoutMs: otpTimeout, refreshBundle: true, fromStep });
        }
        res.json({ success: true, started: runnable.length });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/signups/:id/stop', async (req, res) => {
    if (activeSignupWorkers[req.params.id]) {
        activeSignupWorkers[req.params.id].stop();
        delete activeSignupWorkers[req.params.id];
    }
    res.json({ success: true });
});

app.post('/api/signups/stop-all', async (req, res) => {
    for (const [id, worker] of Object.entries(activeSignupWorkers)) {
        worker.stop();
        delete activeSignupWorkers[id];
    }
    res.json({ success: true });
});

// Promote a completed signup into a real accounts row.
app.post('/api/signups/:id/convert', async (req, res) => {
    try {
        const s = await getSignup(req.params.id);
        if (!s) return res.status(404).json({ error: 'Signup not found' });
        if (!['DONE', 'CONVERTED'].includes(s.status)) {
            return res.status(400).json({ error: `Signup is not completed (status: ${s.status})` });
        }
        const accountId = await convertSignupToAccount(req.params.id);
        io.emit('signup_status', { id: s.id, phone: s.phone, status: 'CONVERTED', lastLog: `Converted to account #${accountId}`, time: new Date().toISOString() });
        res.json({ success: true, accountId });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── REST API: Individual Account Control ─────────────────────────────────────
app.post('/api/accounts/:id/start', async (req, res) => {
    try {
        const account = await getAccount(req.params.id);
        if (!account) return res.status(404).json({ error: 'Account not found' });
        if (account.is_active === 0) return res.status(400).json({ error: 'Cannot start a disabled account' });
        const step = parseInt(req.body.step || 0);
        const otpTimeout = req.body.otpTimeout || 30;
        const config = await getConfig();
        const proxies = await getProxiesForAccount(account.id);
        const proxyUrl = proxies.length > 0 ? proxies[0].proxy_url : null;
        ['ep_signin', 'ep_reserve', 'ep_fileupload'].forEach(k => {
            captchaManager.getSolver(account.id, proxyUrl, config[`${k}_captchaType`], config[`${k}_siteKey`]).fillCaptchaPool();
        });
        await launchWorker(account, config, step, otpTimeout);
        res.json({ success: true, phone: account.phone, step });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/accounts/:id/stop', async (req, res) => {
    try {
        const account = await getAccount(req.params.id);
        if (!account) return res.status(404).json({ error: 'Account not found' });
        const worker = activeWorkers[account.phone];
        if (worker) {
            worker.stop();
            io.emit('token_cleared', { phone: account.phone });
        }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Fire a SINGLE manual Reserve (step 3) or Payment (step 4) request, in parallel with the
// running worker — the OTP-verify loop keeps running untouched. The outcome (and any captcha
// solve) streams to the account's live log. Used when the bot is stuck retrying OTP verify
// but the underlying session is already usable.
app.post('/api/accounts/:id/jump', async (req, res) => {
    try {
        const account = await getAccount(req.params.id);
        if (!account) return res.status(404).json({ error: 'Account not found' });
        const step = parseInt(req.body.step);
        if (![3, 4].includes(step)) return res.json({ success: false, error: 'Invalid step (must be 3=Reserve or 4=Payment)' });
        const worker = activeWorkers[account.phone];
        if (!worker) return res.json({ success: false, error: 'No active worker running for this account' });
        if (worker._manualBusy) return res.json({ success: false, error: 'A manual action is already in progress' });
        // Fire-and-forget: the request may need to solve a captcha (Reserve), so don't block
        // the HTTP response on it. Progress/result is logged to the dashboard.
        if (step === 3) worker.manualReserveOnce().catch(() => { });
        else worker.manualPaymentOnce().catch(() => { });
        res.json({ success: true, message: step === 3 ? 'Manual Reserve triggered' : 'Manual Payment triggered' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/accounts/:id/last-otp', async (req, res) => {
    try {
        const account = await getAccount(req.params.id);
        if (!account) return res.status(404).json({ error: 'Account not found' });
        const client = globalOtpClients[account.phone];
        if (client && client.lastOtp) {
            res.json({ otp: client.lastOtp, time: client.lastOtpTime });
        } else {
            res.json({ otp: null });
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/accounts/:id/pull-booking-config', async (req, res) => {
    try {
        const account = await getAccount(req.params.id);
        if (!account) return res.status(404).json({ error: 'Account not found' });

        const { getStoredToken, saveAppointmentId } = require('./database');
        const storedToken = await getStoredToken(account.id);
        if (!storedToken) return res.status(400).json({ error: 'No active session. Please start the bot to sign in first.' });

        const proxies = await getProxiesForAccount(account.id);
        const proxyUrl = proxies.length > 0 ? proxies[0].proxy_url : null;
        const config = await getConfig();
        const { IvacApi } = require('./api');
        const api = new IvacApi(proxyUrl, config);
        api.setToken(storedToken);

        const configRes = await api.getBookingConfig();
        if (configRes.ok && configRes.data?.data?.appointmentId) {
            const appointmentId = configRes.data.data.appointmentId;
            await saveAppointmentId(account.id, appointmentId);
            res.json({ success: true, appointmentId, message: 'Successfully pulled and saved.' });
        } else {
            res.status(400).json({ error: 'Failed to fetch appointment ID', details: configRes.data });
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Manually set the appointmentId for an account. Saved via the same path as the auto-pull, so
// appointment_date is stamped to today (CURDATE) — the ID is valid today and expires next day,
// matching the daily-expiry the bot enforces in getSavedAppointmentId().
app.post('/api/accounts/:id/set-appointment-id', async (req, res) => {
    try {
        const account = await getAccount(req.params.id);
        if (!account) return res.status(404).json({ error: 'Account not found' });

        const appointmentId = (req.body && req.body.appointmentId != null ? String(req.body.appointmentId) : '').trim();
        if (!appointmentId) return res.status(400).json({ error: 'appointmentId is required' });

        const { saveAppointmentId } = require('./database');
        await saveAppointmentId(account.id, appointmentId);
        res.json({ success: true, appointmentId, message: 'Appointment ID saved for today.' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── REST API: Invoices ───────────────────────────────────────────────────────
// Build an IvacApi bound to this account's stored token + first proxy (same recipe as
// pull-booking-config). Caller must api.close() when done.
async function buildAccountApi(accountId) {
    const { getStoredToken } = require('./database');
    const storedToken = await getStoredToken(accountId);
    if (!storedToken) return { error: 'No active session. Please start the bot to sign in first.' };
    const proxies = await getProxiesForAccount(accountId);
    const proxyUrl = proxies.length > 0 ? proxies[0].proxy_url : null;
    const config = await getConfig();
    const { IvacApi } = require('./api');
    const api = new IvacApi(proxyUrl, config);
    api.setToken(storedToken);
    return { api };
}

// The invoice list arrives in an envelope whose exact shape we don't control — find the
// array inside it and keep only entries that carry a transaction id (the download key).
function extractInvoices(payload) {
    const candidates = [payload, payload?.data, payload?.data?.data, payload?.data?.invoices, payload?.data?.content];
    const arr = candidates.find(Array.isArray) || [];
    return arr.map(item => {
        if (!item || typeof item !== 'object') return null;
        const key = Object.keys(item).find(k => /^(txr_?id|trx_?id|tran_?id|transaction_?id)$/i.test(k));
        return key && item[key] ? { ...item, txrId: String(item[key]) } : null;
    }).filter(Boolean);
}

// Walk a response payload of unknown shape and pull out BGD/appointment numbers. Collects any
// string that looks like a BGD id (e.g. "BGDDV99B5826"), plus the value of common id fields.
function collectBgdNumbers(payload) {
    const found = new Set();
    const idKeys = /^(appointment_?id|bgd_?number|bgd_?no|web_?file_?number|application_?id|tracking_?number)$/i;
    const bgdLike = /^BGD[A-Z0-9]{4,}$/i;
    const walk = (node) => {
        if (node == null) return;
        if (Array.isArray(node)) { node.forEach(walk); return; }
        if (typeof node === 'object') {
            for (const [k, v] of Object.entries(node)) {
                if ((idKeys.test(k) || bgdLike.test(String(v))) && v != null && typeof v !== 'object') {
                    found.add(String(v).trim());
                }
                walk(v);
            }
            return;
        }
        if (bgdLike.test(String(node))) found.add(String(node).trim());
    };
    walk(payload);
    return [...found].filter(Boolean);
}

// Walk a payload of unknown shape and pull out applicant records: each object that carries a
// name (givenName/surName, or applicantName/fullName/cusName) becomes { given, sur, name, bgd },
// with the BGD number inherited from the nearest ancestor that had one (booking-level value,
// applicant-level name).
function extractApplicantRecords(payload) {
    const records = [];
    const givenKey = /^(given_?name|first_?name)$/i;
    const surKey = /^(sur_?name|last_?name)$/i;
    const fullKey = /^(applicant_?name|full_?name|cus_?name)$/i;
    const bgdKey = /^(appointment_?id|bgd_?number|bgd_?no|application_?id)$/i;
    const bgdLike = /^BGD[A-Z0-9]{4,}$/i;

    const walk = (node, inheritedBgd) => {
        if (node == null) return;
        if (Array.isArray(node)) { node.forEach(n => walk(n, inheritedBgd)); return; }
        if (typeof node !== 'object') return;

        // A BGD found at this level flows down to nested applicant records.
        let bgd = inheritedBgd;
        let given = '', sur = '', full = '';
        for (const [k, v] of Object.entries(node)) {
            if (v == null || typeof v === 'object') continue;
            const val = String(v).trim();
            if (bgdKey.test(k) || bgdLike.test(val)) bgd = val;
            if (givenKey.test(k)) given = val;
            else if (surKey.test(k)) sur = val;
            else if (fullKey.test(k)) full = val;
        }
        if (given || sur || full) {
            const name = (given || sur) ? [given, sur].filter(Boolean).join(' ') : full;
            records.push({ given, sur, name, bgd: bgd || null });
        }
        for (const v of Object.values(node)) walk(v, bgd);
    };
    walk(payload, null);
    return records;
}

// Overview button: fetch the account's overview + BGD number and print, per applicant,
// "✅ {BGD} - {given name} {surname}" into the account log.
app.post('/api/accounts/:id/overview', async (req, res) => {
    try {
        const account = await getAccount(req.params.id);
        if (!account) return res.status(404).json({ error: 'Account not found' });

        const built = await buildAccountApi(account.id);
        if (built.error) return res.status(400).json({ error: built.error });
        const api = built.api;

        const emitLog = (level, message) =>
            io.emit('account_log', { phone: account.phone, level, message, time: new Date().toISOString() });

        let records = [];
        try {
            // 1. Names come from the file overview (per-applicant applicantName / given+sur).
            const ovRes = await api.getFileOverview();
            if (ovRes.ok) records = extractApplicantRecords(ovRes.data);
            else emitLog('WARN', `📋 Overview API returned HTTP ${ovRes.status}`);

            // 2. The BGD number (appointmentId) is a booking-level value — pull it and backfill.
            let bgd = records.find(r => r.bgd)?.bgd || null;
            if (!bgd) {
                const cfgRes = await api.getBookingConfig();
                if (cfgRes.ok) bgd = collectBgdNumbers(cfgRes.data)[0] || null;
            }
            if (bgd) records.forEach(r => { if (!r.bgd) r.bgd = bgd; });

            // 3. If the overview gave no applicant names, fall back to the invoice list, which
            //    pairs appointmentId (BGD) with cusName per entry.
            if (!records.length) {
                const invRes = await api.getInvoices();
                if (invRes.ok) records = extractApplicantRecords(invRes.data);
            }
        } finally { api.close(); }

        const lines = records
            .filter(r => r.name)
            .map(r => `✅ ${r.bgd || 'N/A'} - ${r.name}`);

        if (lines.length) {
            lines.forEach(line => emitLog('INFO', line));
        } else {
            emitLog('WARN', '📋 No overview/BGD info found for this account.');
        }
        res.json({ success: true, lines, records });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/accounts/:id/invoices', async (req, res) => {
    try {
        const account = await getAccount(req.params.id);
        if (!account) return res.status(404).json({ error: 'Account not found' });

        const built = await buildAccountApi(account.id);
        if (built.error) return res.status(400).json({ error: built.error });
        const api = built.api;
        try {
            const listRes = await api.getInvoices();
            if (!listRes.ok) {
                return res.status(400).json({ error: `Failed to fetch invoices (HTTP ${listRes.status})`, details: listRes.data });
            }
            const invoices = extractInvoices(listRes.data);
            if (!invoices.length) return res.status(404).json({ error: 'No invoices found for this account' });
            res.json({ success: true, invoices });
        } finally { api.close(); }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/accounts/:id/invoices/:txrId/download', async (req, res) => {
    try {
        const account = await getAccount(req.params.id);
        if (!account) return res.status(404).json({ error: 'Account not found' });

        const txrId = String(req.params.txrId || '');
        if (!/^[\w-]+$/.test(txrId)) return res.status(400).json({ error: 'Invalid txrId' });

        const built = await buildAccountApi(account.id);
        if (built.error) return res.status(400).json({ error: built.error });
        const api = built.api;

        // The invoice-download route is Turnstile-guarded (x-token). Pull a token from the
        // captcha pool — reuse the payment captcha config (same Turnstile widget), falling back
        // to the fileupload one. If neither is configured we try without a token (may 500).
        const config = await getConfig();
        const proxies = await getProxiesForAccount(account.id);
        const proxyUrl = proxies.length > 0 ? proxies[0].proxy_url : null;
        let turnstileToken = null;
        const captchaType = config.ep_payment_captchaType || config.ep_fileupload_captchaType;
        const siteKey = config.ep_payment_siteKey || config.ep_fileupload_siteKey;
        if (siteKey) {
            try {
                const solver = captchaManager.getSolver(account.id, proxyUrl, captchaType, siteKey);
                solver.fillCaptchaPool();
                const result = await solver.getToken();
                turnstileToken = result ? result.token : null;
            } catch (e) {
                logger.warn(`[${account.phone}] Invoice captcha token fetch failed: ${e.message}`);
            }
        }

        let dlRes;
        try { dlRes = await api.downloadInvoice(txrId, turnstileToken); } finally { api.close(); }

        if (!dlRes.ok || !dlRes.body || !dlRes.body.length) {
            const details = typeof dlRes.data === 'string' ? dlRes.data.substring(0, 300) : dlRes.data;
            return res.status(400).json({ error: `Invoice download failed (HTTP ${dlRes.status})`, details });
        }

        // The API is expected to answer with the PDF bytes. If it answered with a JSON
        // error body instead (expired token, wrong txrId), surface that as an error rather
        // than serving JSON bytes under a .pdf name.
        const contentType = String(dlRes.headers?.['content-type'] || dlRes.headers?.['Content-Type'] || '');
        const looksPdf = contentType.includes('pdf') || dlRes.body.slice(0, 5).toString() === '%PDF-';
        if (!looksPdf && (contentType.includes('json') || typeof dlRes.data === 'object')) {
            return res.status(400).json({ error: 'Invoice API did not return a PDF', details: dlRes.data });
        }

        res.setHeader('Content-Type', looksPdf ? 'application/pdf' : 'application/octet-stream');
        res.setHeader('Content-Disposition', `attachment; filename="${account.phone}.pdf"`);
        res.send(dlRes.body);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/accounts/:id/open-browser', async (req, res) => {
    try {
        const account = await getAccount(req.params.id);
        if (!account) return res.status(404).json({ error: 'Account not found' });

        const { pool } = require('./database');
        const [rows] = await pool.query(
            'SELECT access_token, token_expires_at FROM accounts WHERE id = ? AND token_expires_at > NOW()',
            [account.id]
        );
        if (!rows.length || !rows[0].access_token) {
            return res.status(400).json({ error: 'No active session. Please start the bot to sign in first.' });
        }
        const token = rows[0].access_token;
        const expiresAt = new Date(rows[0].token_expires_at).toISOString();

        // Use the SAME engine as the captcha Solver (puppeteer-real-browser) instead of plain
        // puppeteer. Plain puppeteer leaks CDP signals (Runtime.Enable / execution-context) that
        // Cloudflare Turnstile scores as "bot", so the widget never solved in this per-account
        // window. puppeteer-real-browser patches those leaks (see /api/launch-solver above).
        const { connect } = require('puppeteer-real-browser');
        const proxyChain = require('proxy-chain');
        const { formatProxyUrl } = require('./api');

        // 1. Setup Proxy
        // Chrome can't authenticate a SOCKS5 proxy (no --proxy-server creds, and
        // page.authenticate() only answers HTTP 407 — not SOCKS). So we normalize the
        // stored proxy to protocol://user:pass@host:port, then run it through
        // proxy-chain.anonymizeProxy(), which spins up a LOCAL no-auth endpoint that
        // forwards upstream with the right scheme + credentials. Works for authenticated
        // SOCKS5, authenticated HTTP, and no-auth proxies alike — Chrome just talks to
        // the local endpoint, no page.authenticate() needed.
        const { getProxiesForAccount, getActiveApiIps } = require('./database');
        const proxies = await getProxiesForAccount(account.id);
        let proxyArg = null;
        let anonymizedProxyUrl = null;
        if (proxies && proxies.length > 0) {
            const formatted = formatProxyUrl(proxies[0].proxy_url);
            if (formatted) {
                try {
                    // For an auth proxy this returns http://127.0.0.1:<port>; for a no-auth
                    // proxy it returns the original URL unchanged (still valid for Chrome).
                    anonymizedProxyUrl = await proxyChain.anonymizeProxy(formatted);
                    proxyArg = `--proxy-server=${anonymizedProxyUrl}`;
                    logger.info(`[${account.phone}] Browser proxy ready (${formatted.split('://')[0]}://…) via ${anonymizedProxyUrl}`);
                } catch (e) {
                    logger.error(`[${account.phone}] Failed to set up browser proxy: ${e.message}`);
                    return res.status(500).json({ error: `Proxy setup failed: ${e.message}` });
                }
            }
        }

        // 2. Setup EC2 Bypass
        const bypassIps = await getActiveApiIps();
        let ec2IpArg = null;
        if (bypassIps && bypassIps.length > 0) {
            // Force Chrome to connect to the EC2 IP directly for the API, bypassing Cloudflare
            ec2IpArg = `--host-rules=MAP api.ivacbd.com ${bypassIps[0]}`;
        }

        // 3. Generate Device ID
        const chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        let xDeviceId = '';
        for (let i = 0; i < 20; i++) xDeviceId += chars[Math.floor(Math.random() * chars.length)];

        // Tile windows into the detected screen size. We track OCCUPIED slot indices in a Set
        // (freed when a window closes — see the disconnect handler below) and assign the lowest free
        // slot, so closed positions get reused instead of the window drifting off-screen. Once the
        // grid is full, extra windows CASCADE with a small diagonal offset, clamped to stay on-screen.
        const width = 640, height = 520;
        const { width: scrW, height: scrH } = getScreenSize();
        const cols = Math.max(1, Math.floor(scrW / width));
        const gridRows = Math.max(1, Math.floor(scrH / height));
        const capacity = cols * gridRows;

        global.openBrowserSlots = global.openBrowserSlots || new Set();
        let slot = 0;
        while (global.openBrowserSlots.has(slot)) slot++;
        global.openBrowserSlots.add(slot);

        let x, y;
        if (slot < capacity) {
            x = (slot % cols) * width;
            y = Math.floor(slot / cols) * height;
        } else {
            const over = slot - capacity;
            const step = 30;
            x = (over * step) % Math.max(1, scrW - width);
            y = (over * step) % Math.max(1, scrH - height);
        }

        // Keep this arg set MINIMAL and clean — same philosophy as the Solver. Flags like
        // --no-sandbox, --disable-setuid-sandbox, --disable-web-security and
        // --disable-features=IsolateOrigins all degrade the Turnstile score (and the
        // "unsupported command-line flag" warning bar is itself a bot tell), which is why
        // Turnstile reported "Verification failed". automation flags are handled by
        // puppeteer-real-browser, so we don't add --disable-blink-features here either.
        const args = [
            `--window-size=${width},${height}`,
            `--window-position=${x},${y}`,
            '--ignore-certificate-errors',
        ];
        if (proxyArg) args.push(proxyArg);
        if (ec2IpArg) {
            args.push(ec2IpArg);
            if (proxyArg) args.push('--proxy-bypass-list=api.ivacbd.com');
        }

        // turnstile:true lets puppeteer-real-browser auto-solve the Turnstile widget on the
        // appointment page. Prefer the bundled Chrome-for-Testing (scores Turnstile best, same as
        // the Solver) and fall back to installed Chrome if it isn't present.
        let browser, page;
        try {
            ({ browser, page } = await connect({
                headless: false,
                turnstile: true,
                customConfig: { chromePath: (resolveSolverChromePath() || resolveChromePath()) || undefined },
                connectOption: { defaultViewport: null },
                args,
            }));
        } catch (e) {
            // Launch failed — release the reserved tiling slot so it isn't leaked off-screen.
            global.openBrowserSlots.delete(slot);
            throw e;
        }
        // When this browser window is closed: release its tiling slot (so the position is reused
        // instead of new windows drifting off-screen) and free the local proxy bridge if any.
        browser.on('disconnected', () => {
            global.openBrowserSlots.delete(slot);
            if (anonymizedProxyUrl) {
                proxyChain.closeAnonymizedProxy(anonymizedProxyUrl, true).catch(() => { });
            }
        });
        // navigator.webdriver / AutomationControlled / --enable-automation are all handled by
        // puppeteer-real-browser, so the manual webdriver strip and ignoreDefaultArgs are gone.

        await page.goto('https://appointment.ivacbd.com', { waitUntil: 'domcontentloaded' });

        const stateObj = {
            "state": {
                "token": token,
                "userId": "00381d55-420a-40dd-b16e-f8114c8ff9f3",
                "expiresAt": expiresAt,
                "isAuthenticated": true,
                "isVerified": true,
                "requestId": null,
                "phone": account.phone,
                "password": null,
                "otpSentAt": 1780139223044
            },
            "version": 0
        };

        await page.evaluate((stateStr, deviceId) => {
            localStorage.setItem('auth-storage', stateStr);
            localStorage.setItem('x-device-id', deviceId);
            window.location.reload();
        }, JSON.stringify(stateObj), xDeviceId);

        res.json({ success: true, message: 'Browser opened with injected local storage.' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Launch Captcha Solver with Domain Spoofing
app.post('/api/launch-solver', async (req, res) => {
    try {
        // puppeteer-real-browser launches Chrome through rebrowser-puppeteer, which patches the
        // CDP leaks (Runtime.Enable / execution-context) that plain puppeteer can't hide — those
        // are what Turnstile scores as "bot" even after stripping navigator.webdriver. We DON'T
        // use its built-in turnstile solver (turnstile:false): captcha.html is a MASS solver with
        // many widgets per page, so the custom multi-widget auto-click loop below stays in charge.
        const { connect } = require('puppeteer-real-browser');
        const { formatProxyUrl } = require('./api');

        // Solver proxy is configurable from Settings (config key `solver_proxy`). Accepts any of the
        // formats formatProxyUrl() understands (ip:port, ip:port:user:pass, user:pass@host:port, or a
        // full proxy URL). If the key is unset we fall back to the built-in default so existing setups
        // keep working; if it's set but BLANK the user has explicitly opted into running proxyless.
        const DEFAULT_SOLVER_PROXY = 'http://64b7bde17e85e0475ace__cr.bd:03474834ebb48a2b@gw.dataimpulse.com:823';
        const config = await getConfig();
        const rawSolverProxy = Object.prototype.hasOwnProperty.call(config, 'solver_proxy')
            ? (config.solver_proxy || '')
            : DEFAULT_SOLVER_PROXY;

        let proxyOpt;            // undefined => proxyless launch
        let proxyLabel = 'proxyless';
        const formattedProxy = rawSolverProxy.trim() ? formatProxyUrl(rawSolverProxy.trim()) : null;
        if (formattedProxy) {
            try {
                const u = new URL(formattedProxy);
                proxyOpt = {
                    host: u.hostname,
                    port: Number(u.port),
                    username: u.username ? decodeURIComponent(u.username) : undefined,
                    password: u.password ? decodeURIComponent(u.password) : undefined,
                };
                proxyLabel = `${u.hostname}:${u.port}`;
            } catch (e) {
                logger.warn(`🧩 [Solver] Invalid solver_proxy "${rawSolverProxy}" (${e.message}) — launching proxyless.`);
            }
        }
        logger.info(`🧩 [Solver] Launching with proxy: ${proxyLabel}`);

        const { browser, page } = await connect({
            headless: false,
            turnstile: true,                  // library auto-solves Turnstile; custom loop below still runs as backup
            // Reuse the bundled Chrome-for-Testing that already scored Turnstile best (server.js:122).
            // Tip: with rebrowser's leak patches, real installed Chrome may now score as well or better —
            // drop chromePath to let puppeteer-real-browser auto-pick installed Chrome if you want to test that.
            customConfig: { chromePath: resolveSolverChromePath() || undefined },
            // Built-in authenticated proxy — replaces the old --proxy-server arg + page.authenticate().
            // undefined when proxyless so puppeteer-real-browser launches without a proxy.
            proxy: proxyOpt,
            connectOption: { defaultViewport: null },
            args: [
                '--host-rules=MAP appointment.ivacbd.com 127.0.0.1',
                '--proxy-bypass-list=appointment.ivacbd.com,127.0.0.1,localhost',
                '--ignore-certificate-errors',
                '--window-size=1000,800',
                '--max-active-webgl-contexts=100',
            ],
        });
        // navigator.webdriver, AutomationControlled and --enable-automation are all handled by
        // rebrowser/real-browser, so the manual webdriver strip + ignoreDefaultArgs are no longer needed.

        // This will route to our local server due to the host-rule mapping!
        await page.goto(`http://appointment.ivacbd.com:${PORT}/captcha.html`, { waitUntil: 'domcontentloaded' });

        // ─── Auto-click Turnstile checkboxes (acts like a manual click) ──────────────
        // Cloudflare Turnstile renders its iframe + checkbox inside a SHADOW DOM, so a plain
        // querySelectorAll('iframe') (page.$$('iframe')) finds 0 — it can't pierce shadow roots.
        // Instead we target the widget container divs WE created in captcha.html (#cf-widget-N /
        // .widget-container) — those are in the normal DOM and have the exact position/size of
        // the widget. We then click the checkbox by COORDINATE (far left, vertically centered)
        // using a real Puppeteer mouse event, which the browser routes into the shadow iframe.
        // Best-effort: Turnstile detects automation, so a clean proxy/fingerprint still matters;
        // CapMonster (capmonster_key) / primary provider (primary_captcha_url) stay the reliable path.
        logger.info('🤖 [Solver] Auto-click loop started.');
        const lastClickAt = new Map();  // widget key -> last click ts (re-click if still unsolved)
        const prevSolved = new Map();    // widget key -> was solved on the previous scan (reset detection)
        const CLICK_COOLDOWN_MS = 8000;
        let cycle = 0;
        const autoClickLoop = async () => {
            while (true) {
                if (typeof page.isClosed === 'function' && page.isClosed()) return;
                cycle++;
                try {
                    // Prefer the exact render targets; fall back to the container, then raw iframes.
                    let handles = await page.$$('[id^="cf-widget-"]');
                    if (handles.length === 0) handles = await page.$$('.widget-container');
                    if (handles.length === 0) handles = await page.$$('iframe');

                    if (cycle <= 3 || cycle % 10 === 0) {
                        logger.info(`🤖 [Solver] scan #${cycle}: ${handles.length} captcha widget(s) on page.`);
                    }
                    let clicks = 0;
                    for (let i = 0; i < handles.length; i++) {
                        const handle = handles[i];
                        // Read the widget's stable id + solved flag in one pass.
                        // (captcha.html marks a widget data-solved="1" when solved, and removes it on reset.)
                        const info = await handle.evaluate(el => ({
                            id: el.id || '',
                            solved: el.getAttribute('data-solved') === '1',
                        })).catch(() => null);
                        if (!info) continue;

                        // Stable per-widget key. Key by the container id, NOT screen position — the widget
                        // sits at the same spot after a reset, so a position key kept its stale click
                        // timestamp and left it stuck on cooldown (the "doesn't click the new captcha" bug).
                        let wkey = info.id;
                        if (!wkey) {
                            const pbox = await handle.boundingBox().catch(() => null);
                            wkey = pbox ? `${Math.round(pbox.x)},${Math.round(pbox.y)}` : `idx${i}`;
                        }

                        // Detect a solved → unsolved transition (a manual or backend RESET) and re-arm the
                        // widget by dropping its cooldown, so the fresh captcha gets clicked on this scan
                        // instead of waiting out the previous click's cooldown window.
                        if (prevSolved.get(wkey) && !info.solved) {
                            lastClickAt.delete(wkey);
                            logger.info(`🤖 [Solver] Widget ${wkey} was reset — re-arming auto-click.`);
                        }
                        prevSolved.set(wkey, info.solved);

                        if (info.solved) continue;
                        try { await handle.evaluate(el => el.scrollIntoView({ block: 'center', inline: 'center' })); } catch (e) { continue; }
                        const box = await handle.boundingBox().catch(() => null);
                        if (!box || box.width < 50 || box.height < 30) continue; // not laid out yet
                        const now = Date.now();
                        if (now - (lastClickAt.get(wkey) || 0) < CLICK_COOLDOWN_MS) continue;
                        lastClickAt.set(wkey, now);
                        const x = box.x + 34;                 // checkbox ≈ 30-40px from the widget's left
                        const y = box.y + box.height / 2;     // vertically centered
                        await page.mouse.move(x, y);
                        await page.mouse.click(x, y, { delay: 60 });
                        clicks++;
                        logger.info(`🤖 [Solver] Clicked widget ${wkey} at (${Math.round(x)}, ${Math.round(y)}).`);
                    }
                    // Visible feedback inside the solver window itself (server logs are elsewhere).
                    await page.evaluate((c, scan) => {
                        const s = document.getElementById('status');
                        if (s && c > 0) s.innerText = `🤖 Auto-clicked ${c} captcha(s) at ${new Date().toLocaleTimeString()} (scan ${scan})`;
                    }, clicks, cycle).catch(() => { });

                    // ── Keep the cursor MOVING over an unsolved captcha until it solves ──────
                    // Turnstile scores live pointer motion over the widget, so instead of one
                    // static park we gently jiggle the cursor around the first unsolved widget
                    // for the whole inter-scan wait. Pure instant mouse.move steps (no glide,
                    // no clicks) — keeps motion alive without slowing/stalling the solve.
                    let hoverHandle = null;
                    for (let h = 0; h < handles.length; h++) {
                        const solved = await handles[h].evaluate(el => el.getAttribute('data-solved') === '1').catch(() => true);
                        if (!solved) { hoverHandle = handles[h]; break; }
                    }
                    let hb = null;
                    if (hoverHandle) hb = await hoverHandle.boundingBox().catch(() => null);

                    const waitUntil = Date.now() + 700;
                    if (hb) {
                        // Small wandering jiggle inside the widget bounds, ~every 90ms, until the
                        // next scan. Stays within the widget so the cursor is always "on captcha".
                        const cx = hb.x + hb.width / 2;
                        const cy = hb.y + hb.height / 2;
                        const rx = Math.min(hb.width / 2 - 4, 28);
                        const ry = Math.min(hb.height / 2 - 4, 14);
                        while (Date.now() < waitUntil) {
                            const ang = Math.random() * Math.PI * 2;
                            const jx = cx + Math.cos(ang) * rx * Math.random();
                            const jy = cy + Math.sin(ang) * ry * Math.random();
                            await page.mouse.move(jx, jy);
                            await new Promise(r => setTimeout(r, 90));
                        }
                    } else {
                        // Nothing unsolved to hover — just idle until the next scan.
                        await new Promise(r => setTimeout(r, 700));
                    }
                    continue; // skip the trailing fixed sleep; we already waited above
                } catch (e) {
                    if (cycle <= 3) logger.warn(`🤖 [Solver] auto-click error: ${e.message}`);
                }
                await new Promise(r => setTimeout(r, 700));
            }
        };
        autoClickLoop();

        res.json({ success: true, message: 'Solver launched with auto-click enabled!' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/accounts/:id/check-proxy', async (req, res) => {
    try {
        const account = await getAccount(req.params.id);
        if (!account) return res.status(404).json({ error: 'Account not found' });

        const proxies = await getProxiesForAccount(account.id);
        if (!proxies || proxies.length === 0) {
            return res.json({ success: false, error: 'No proxies assigned to this account' });
        }

        const proxyUrl = proxies[0].proxy_url;
        const { formatProxyUrl, friendlyProtocol } = require('./api');
        const formattedProxy = formatProxyUrl(proxyUrl);
        const proxyType = formattedProxy ? (formattedProxy.startsWith('socks5') ? 'SOCKS5' : 'HTTP') : 'Unknown';
        
        // Match the bot's actual logic: force HTTP/3 for SOCKS5, HTTP/2 for HTTP proxies
        const httpVersionToUse = proxyType === 'SOCKS5' ? 'h3' : 'h2';

        const startTime = Date.now();
        const httpcloak = require('httpcloak');

        // Build the session OUTSIDE the try so we can guarantee close() in finally.
        // A leaked Go-backed session keeps live QUIC/TLS connections + native threads
        // and pins the event loop open — repeated proxy tests would starve the box.
        let session = null;
        try {
            session = new httpcloak.Session({
                preset: 'chrome-116-windows',
                proxy: formattedProxy || '',
                httpVersion: httpVersionToUse,
                timeout: 10
            });

            const response = await session.request('GET', 'https://cloudflare.com/cdn-cgi/trace', {
                headers: { 'accept': '*/*' }
            });

            if (response.statusCode >= 200 && response.statusCode < 300) {
                const text = response.text || '';
                const ipMatch = text.match(/ip=([^\n]+)/);
                const ip = ipMatch ? ipMatch[1].trim() : 'Unknown';
                
                const httpMatch = text.match(/http=([^\n]+)/);
                const cfHttp = httpMatch ? httpMatch[1].trim().toUpperCase() : '';
                
                const actualProto = friendlyProtocol(response.protocol);
                const displayProto = cfHttp ? `${actualProto} (Verified by Cloudflare as ${cfHttp})` : actualProto;
                
                return res.json({
                    success: true,
                    ip: ip,
                    time: Date.now() - startTime,
                    type: proxyType,
                    protocol: displayProto
                });
            } else {
                return res.json({
                    success: false,
                    error: `HTTP ${response.statusCode}`,
                    time: Date.now() - startTime
                });
            }
        } catch (err) {
            return res.json({
                success: false,
                error: err.message || 'Connection failed',
                time: Date.now() - startTime
            });
        } finally {
            if (session) { try { session.close(); } catch (e) { /* ignore */ } }
        }
    } catch (e) {
        return res.json({ success: false, error: e.message });
    }
});

// ─── REST API: Auto-Start Scheduler ───────────────────────────────────────────
app.post('/api/bot/autostart', async (req, res) => {
    try {
        const { time, captchaWarmTime, otpTimeout, steps, offsetMs } = req.body; // "HH:MM:SS" 24h
        if (!time) return res.status(400).json({ error: 'time required (HH:MM:SS)' });

        // Cancel previous timers
        if (autoStartTimer) clearTimeout(autoStartTimer);
        if (captchaWarmTimer) clearTimeout(captchaWarmTimer);
        autoStartOtpTimeout = parseInt(otpTimeout) || 30;

        const now = new Date();
        const [h, m, s] = time.split(':').map(Number);
        const target = new Date();
        target.setHours(h, m, s || 0, 0); // Explicitly 0 milliseconds
        if (target <= now) target.setDate(target.getDate() + 1);

        // Apply fine-tuned millisecond offset
        if (offsetMs !== undefined && !isNaN(offsetMs)) {
            target.setTime(target.getTime() + parseInt(offsetMs));
        }

        const diff = target.getTime() - now.getTime();

        // Schedule captcha pre-warm (default 90s before start)
        const warmOffset = captchaWarmTime ? (() => {
            const [wh, wm, ws] = captchaWarmTime.split(':').map(Number);
            const warmTarget = new Date();
            warmTarget.setHours(wh, wm, ws || 0, 0);
            if (warmTarget <= now) warmTarget.setDate(warmTarget.getDate() + 1);
            return warmTarget.getTime() - now.getTime();
        })() : diff - 90000;

        if (warmOffset > 0) {
            captchaWarmTimer = setTimeout(async () => {
                logger.info('⏱️ Auto-warming captcha pool...');
                io.emit('server_message', { type: 'warn', text: '⏱️ Pre-warming captcha pool...' });

                // Clear old captchas and calculate exact pool size needed
                const currentAccounts = await getAccounts();
                const active = currentAccounts.filter(a => a.status !== 'COMPLETED' && a.is_active === 1);
                const config = await getConfig();
                for (const account of active) {
                    const proxies = await getProxiesForAccount(account.id);
                    const proxyUrl = proxies.length > 0 ? proxies[0].proxy_url : null;
                    ['ep_signin', 'ep_reserve', 'ep_payment'].forEach(k => {
                        if (!config[`${k}_siteKey`]) return; // payment captcha optional — skip when unconfigured
                        const solver = captchaManager.getSolver(account.id, proxyUrl, config[`${k}_captchaType`], config[`${k}_siteKey`]);
                        solver.clearPool();
                        solver.fillCaptchaPool();
                    });
                }
            }, warmOffset);
        }

        const accounts = await getAccounts();

        // Precision Two-Stage Auto-Start Preparation
        const prepareAndWarmup = async () => {
            autoStartTimer = null;
            const currentOtpTimeout = autoStartOtpTimeout;
            const active = accounts.filter(a => a.status !== 'COMPLETED' && a.is_active === 1);
            const config = await getConfig();

            // Prepare workers instantly
            const workers = [];
            for (const account of active) {
                if (activeWorkers[account.phone]) {
                    activeWorkers[account.phone].stop();
                    delete activeWorkers[account.phone];
                    io.emit('token_cleared', { phone: account.phone });
                }
                const proxies = await getProxiesForAccount(account.id);
                const otpClient = ensureOtpClient(account.phone);
                const step = (steps && steps[account.phone] !== undefined) ? steps[account.phone] : 0;
                const worker = new BotWorker(account, proxies, config, io, step, currentOtpTimeout, otpClient);
                workers.push(worker);
            }

            // Return a function that actually executes the bots perfectly on time
            return () => {
                logger.info('🚀 Auto-start triggered! Exact Time: ' + new Date().toISOString());
                io.emit('server_message', { type: 'info', text: '🚀 Auto-start triggered!' });

                for (const worker of workers) {
                    activeWorkers[worker.account.phone] = worker;
                    worker.run().finally(() => {
                        delete activeWorkers[worker.account.phone];
                        broadcastState();
                    });
                }
                broadcastState();
            };
        };

        if (diff > 5000) {
            // Stage 1: Coarse timeout to wake up 5 seconds before target
            autoStartTimer = setTimeout(async () => {
                // Prepare bots instantly
                const executeLaunch = await prepareAndWarmup();

                // Stage 2: High precision spin-lock/polling for the final milliseconds
                const exactTargetTime = target.getTime();
                const precisionCheck = setInterval(() => {
                    if (Date.now() >= exactTargetTime) {
                        clearInterval(precisionCheck);
                        executeLaunch();
                    }
                }, 1); // Check every 1 millisecond
            }, diff - 5000); // Wake up 5 seconds early
        } else {
            // If less than 5s away, prepare immediately then precision check
            const executeLaunch = await prepareAndWarmup();
            const exactTargetTime = target.getTime();
            autoStartTimer = setInterval(() => {
                if (Date.now() >= exactTargetTime) {
                    clearInterval(autoStartTimer);
                    executeLaunch();
                }
            }, 1);
        }

        broadcastState();
        const startIn = Math.round(diff / 1000);
        res.json({ success: true, startsIn: startIn, target: target.toISOString() });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bot/autostart/cancel', (req, res) => {
    if (autoStartTimer) clearTimeout(autoStartTimer);
    if (captchaWarmTimer) clearTimeout(captchaWarmTimer);
    autoStartTimer = null;
    captchaWarmTimer = null;
    autoStartOtpTimeout = 30;
    io.emit('server_message', { type: 'warn', text: 'Auto-start cancelled.' });
    broadcastState();
    res.json({ success: true });
});

// ─── REST API: Cipher Keys ────────────────────────────────────────────────────
app.get('/api/cipher/status', (req, res) => {
    try {
        res.json(getCachedCipherInfo());
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/cipher/pull', async (req, res) => {
    try {
        const logs = [];
        const result = await pullCipherKeys((msg) => {
            logs.push(msg);
            logger.info(`[CipherKeys] ${msg}`);
        });
        res.json({ success: true, ...result, logs });
        maybeRunProbeAfterCipher('manual pull'); // chain: refresh endpoints after keys
    } catch (e) {
        logger.error(`[CipherKeys] Pull failed: ${e.message}`);
        res.status(500).json({ error: e.message });
    }
});

// Auto-pull: keep retrying the bundle until the cipher server stops 403'ing.
// Starts a background loop and returns immediately; progress + state changes are
// pushed to the dashboard over socket.io ('cipher_autopull' events).
app.post('/api/cipher/auto-pull/start', (req, res) => {
    try {
        const { intervalMs, maxAttempts, workers } = req.body || {};
        const status = startAutoPull(
            { emit: (event) => { io.emit('cipher_autopull', event); if (event.type === 'success') maybeRunProbeAfterCipher('auto-pull'); } },
            { intervalMs, maxAttempts, workers }
        );
        res.json({ success: true, ...status });
    } catch (e) {
        logger.error(`[CipherKeys] Auto-pull start failed: ${e.message}`);
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/cipher/auto-pull/stop', (req, res) => {
    try {
        const stopped = stopAutoPull();
        res.json({ success: true, stopped, ...getAutoPullStatus() });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/cipher/auto-pull/status', (req, res) => {
    try {
        res.json(getAutoPullStatus());
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── REST API: Bundle Probe (endpoint/header auto-adjust) ─────────────────────
// Runs bundleProbe to learn the current week's real requests off the running site bundle, then
// merges them into the ep_* config the bot runs on (probeMapper). Two modes:
//   • auto     — hands-free synthetic offline walk (no login/slot needed)
//   • attended — opens a browser you drive; captures your real requests; applies when you close it
let _probeState = { running: false, mode: null, startedAt: null };

// Run the auto (offline) probe and merge the result into config. Shared by the /api/probe/run
// route and the post-cipher chain. Fire-and-forget friendly; guards against concurrent runs.
async function runProbeAutoAndApply() {
    if (_probeState.running) return { ok: false, skipped: 'a probe is already running' };
    const { probeBundle } = require('./bundleProbe');
    const { applyCapture } = require('./probeMapper');
    const emit = (level, msg) => io.emit('probe_log', { level, msg });
    _probeState = { running: true, mode: 'auto', startedAt: new Date().toISOString() };
    try {
        const r = await probeBundle({ onLog: emit, graceMs: 8000 });
        const applied = await applyCapture(r.outFile, (m) => emit('info', m));
        io.emit('probe_done', { mode: 'auto', count: r.requests.length, applied: applied.updated });
        return { ok: true, count: r.requests.length, applied: applied.updated };
    } catch (e) {
        emit('error', `Probe failed: ${e.message}`);
        logger.error(`[Probe] auto run failed: ${e.message}`);
        return { ok: false, error: e.message };
    } finally {
        _probeState = { running: false, mode: null, startedAt: null };
    }
}

// After a successful cipher key extract, auto-run the probe to refresh endpoints/headers too —
// the two rotate together. Gated by config `probe_after_cipher` (default on) and best-effort
// (a probe failure never affects the cipher pull; when the site is off it just logs and moves on).
async function maybeRunProbeAfterCipher(reason) {
    try {
        const cfg = await getConfig();
        if (String(cfg.probe_after_cipher ?? '1') === '0') return;
        if (_probeState.running) return;
        io.emit('probe_log', { level: 'info', msg: `🔗 Cipher keys updated (${reason}) — auto-running probe to refresh endpoints…` });
        runProbeAutoAndApply(); // fire-and-forget
    } catch (e) { logger.warn(`[Probe] post-cipher trigger skipped: ${e.message}`); }
}

app.get('/api/probe/status', async (req, res) => {
    try {
        const file = require('path').join(__dirname, 'probe-capture.json');
        let capture = null;
        try { capture = JSON.parse(require('fs').readFileSync(file, 'utf8')); } catch (e) { /* none yet */ }
        const cfg = await getConfig();
        res.json({
            running: _probeState.running, mode: _probeState.mode, startedAt: _probeState.startedAt,
            appliedAt: cfg.probe_applied_at || null,
            lastCapture: capture ? {
                probedAt: capture.probedAt, mode: capture.mode || 'synthetic', count: capture.count,
                steps: (capture.requests || []).map((r) => r.step || 'other'),
            } : null,
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/probe/run', async (req, res) => {
    if (_probeState.running) return res.status(409).json({ error: 'a probe is already running' });
    const mode = (req.body && req.body.mode) === 'attended' ? 'attended' : 'auto';
    const { probeBundle, probeAttended } = require('./bundleProbe');
    const { applyCapture } = require('./probeMapper');
    const emit = (level, msg) => io.emit('probe_log', { level, msg });

    if (mode === 'attended') {
        // Fire-and-forget: open the browser, capture as the operator drives, apply on close.
        _probeState = { running: true, mode, startedAt: new Date().toISOString() };
        res.json({ started: true, mode });
        probeAttended({ onLog: emit })
            .then(async (r) => {
                emit('info', `Attended capture done (${r.count} request(s)). Applying to config…`);
                const applied = await applyCapture(r.outFile, (m) => emit('info', m));
                io.emit('probe_done', { mode, count: r.count, applied: applied.updated });
            })
            .catch((e) => emit('error', `Attended probe failed: ${e.message}`))
            .finally(() => { _probeState = { running: false, mode: null, startedAt: null }; });
        return;
    }

    // auto mode: run the synthetic walk to completion, then apply.
    const result = await runProbeAutoAndApply();
    if (result.ok) res.json({ success: true, mode, count: result.count, applied: result.applied });
    else res.status(500).json({ error: result.error || result.skipped || 'probe failed' });
});

// Re-apply the last capture on disk to config without re-running the browser.
app.post('/api/probe/apply', async (req, res) => {
    try {
        const { applyCapture } = require('./probeMapper');
        const logs = [];
        const applied = await applyCapture(undefined, (m) => logs.push(m));
        res.json({ success: true, applied: applied.updated, unchanged: applied.unchanged, logs });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/cipher/test', (req, res) => {
    try {
        const { token, flow, action } = req.body;
        if (!token) return res.status(400).json({ error: 'token required' });
        const validFlow = flow === 'reserve' ? 'reserve' : 'signin';
        if (action === 'decrypt') {
            res.json(testDecrypt(token, validFlow));
        } else {
            res.json(testEncrypt(token, validFlow));
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── REST API: Captcha Pool ───────────────────────────────────────────────────
app.post('/api/captcha/fill', async (req, res) => {
    try {
        const currentAccounts = await getAccounts();
        const active = currentAccounts.filter(a => a.status !== 'COMPLETED' && a.is_active === 1);
        const config = await getConfig();
        for (const account of active) {
            const proxies = await getProxiesForAccount(account.id);
            const proxyUrl = proxies.length > 0 ? proxies[0].proxy_url : null;
            ['ep_signin', 'ep_reserve', 'ep_payment'].forEach(k => {
                if (!config[`${k}_siteKey`]) return; // payment captcha optional — skip when unconfigured
                captchaManager.getSolver(account.id, proxyUrl, config[`${k}_captchaType`], config[`${k}_siteKey`]).fillCaptchaPool();
            });
        }
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/captcha/status', (req, res) => {
    res.json(captchaManager.getGlobalPoolStatus());
});

// ─── REST API: CapMonster Balance ─────────────────────────────────────────────
app.post('/api/capmonster/balance', async (req, res) => {
    try {
        const { key } = req.body;
        if (!key) return res.status(400).json({ error: 'API key required' });

        const { gotScraping } = await import('got-scraping');
        const response = await gotScraping.post('https://api.capmonster.cloud/getBalance', {
            json: { clientKey: key },
            responseType: 'json',
            throwHttpErrors: false
        });

        if (response.body && response.body.errorId === 0) {
            res.json({ success: true, balance: response.body.balance });
        } else {
            res.json({ success: false, error: response.body?.errorCode || 'Failed to get balance' });
        }
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ─── Socket.IO ────────────────────────────────────────────────────────────────
io.on('connection', async (socket) => {
    logger.info(`Dashboard connected: ${socket.id}`);
    socket.emit('bot_state', { running: Object.keys(activeWorkers), autoStart: autoStartTimer !== null });
    // Send recent log history for each account so the dashboard loads previous entries
    try {
        const accounts = await getAccounts();
        for (const account of accounts) {
            const logs = await getRecentLogs(account.phone, 200);
            for (const entry of logs) {
                socket.emit('account_log', {
                    phone: account.phone,
                    level: entry.level,
                    message: entry.message,
                    time: entry.created_at
                });
            }
        }
    } catch (e) { /* silence */ }

    // Manual OTP Injection. `type` ('email' | 'sms') is optional — used by the signup flow so a
    // manually-entered email OTP satisfies the email-channel wait; omitted for the booking flow.
    socket.on('manual_otp', ({ phone, otp, type }) => {
        if (globalOtpClients[phone]) {
            globalOtpClients[phone].injectOtp(otp, type || null);
        } else {
            logger.warn(`No active OTP client found for manual injection on ${phone}`);
        }
    });

    // Mass Manual Captcha Injection
    socket.on('manual_captcha_solved', ({ widgetId, token }) => {
        const { captchaManager } = require('./captcha');
        captchaManager.addGlobalManualToken(widgetId, token);
    });
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.DASHBOARD_PORT || 3000;

async function main() {
    await initDb();
    await loadCipherKeys(); // Load cached cipher keys from DB

    // Set global captcha reset callback
    const { captchaManager } = require('./captcha');
    captchaManager.setResetCallback((widgetId) => {
        io.emit('reset_captcha_widget', { widgetId });
    });

    // Load active OTP servers so every account connects to all of them
    activeOtpServers = await getActiveOtpServers();

    // Connect OTP clients for all active accounts instantly at boot
    const accounts = await getAccounts();
    accounts.forEach(a => {
        if (a.is_active === 1) ensureOtpClient(a.phone);
    });

    // Daily log cleanup: delete entries older than 1 day, every 6 hours
    cleanOldLogs();
    setInterval(cleanOldLogs, 6 * 60 * 60 * 1000);
    server.listen(PORT, () => logger.info(`🌐 Dashboard running at http://localhost:${PORT}`));
}

main().catch(err => { logger.error(`Fatal error: ${err.message}`); process.exit(1); });

module.exports = { io };
