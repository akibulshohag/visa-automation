const axios = require('axios');
const { logger, getConfig } = require('./database');
const { formatProxyUrl } = require('./api');

const CAPTCHA_SOLVER_BASE_API = 'https://api.capmonster.cloud/';
const GOOGLE_RECAPTCHA_SITE_KEY = '0x4AAAAAACghKkJHL1t7UkuZ';
const WEBSITE_URL = 'https://appointment.ivacbd.com/signin';

class CaptchaSolver {
    constructor(clientKey, accountId, proxyUrl, type, siteKey) {
        this.clientKey = clientKey;
        this.accountId = accountId;
        this.type = type || 'TurnstileTask';
        this.siteKey = siteKey;
        this.pool = [];
        this.CAPTCHA_POOL_MAX = 1; // minimum 4 per account
        this.filling = 0;

        this.updateProxy(proxyUrl);

        // Auto-remove expired tokens every 10 seconds (120000 ms = 2 mins)
        this.interval = setInterval(() => {
            const now = Date.now();
            const originalLength = this.pool.length;
            this.pool = this.pool.filter(e => now < e.expiresAt);

            if (this.pool.length < originalLength) {
                logger.info(`🗑️ [Captcha Pool Acc:${this.accountId}] Removed ${originalLength - this.pool.length} expired token(s). Pool remaining: ${this.pool.length}/${this.CAPTCHA_POOL_MAX}`);
            }

        }, 10000);
    }

    updateProxy(proxyUrl) {
        this.proxyUrl = proxyUrl;
        this.proxyDetails = this.parseProxy(proxyUrl);
        if (proxyUrl) {
            logger.info(`🔄 [Captcha Pool Acc:${this.accountId}] Using Proxy: ${this.proxyDetails ? this.proxyDetails.proxyAddress : 'Invalid Proxy'}`);
        } else {
            logger.info(`⚠️ [Captcha Pool Acc:${this.accountId}] No proxy assigned, using Proxyless.`);
        }
    }

    parseProxy(proxyStr) {
        if (!proxyStr) return null;
        try {
            const formatted = formatProxyUrl(proxyStr);
            if (!formatted) return null;
            const parsed = new URL(formatted);
            return {
                proxyType: parsed.protocol.replace(':', ''),
                proxyAddress: parsed.hostname,
                proxyPort: parsed.port ? parseInt(parsed.port) : 80,
                proxyLogin: parsed.username ? decodeURIComponent(parsed.username) : undefined,
                proxyPassword: parsed.password ? decodeURIComponent(parsed.password) : undefined
            };
        } catch (e) {
            logger.error(`[Captcha Pool Acc:${this.accountId}] Failed to parse proxy ${proxyStr}: ${e.message}`);
            return null;
        }
    }

    setPoolSize(newMax) {
        // Ignored for individual solvers, we maintain a strict minimum of 4
        this.CAPTCHA_POOL_MAX = Math.max(newMax, 2);
    }

    clearPool() {
        this.pool = [];
        logger.info(`🗑️ [Captcha Pool Acc:${this.accountId}] Forcibly cleared old tokens. Rebuilding fresh...`);
    }

    async createTask() {
        try {
            let actualType = this.type;
            const config = await getConfig();
            const clientKey = config.capmonster_key || this.clientKey;

            const taskPayload = {
                type: actualType,
                websiteURL: WEBSITE_URL,
                websiteKey: this.siteKey
            };

            // Solve THROUGH the same proxy the sign-in/reserve request will be submitted from.
            // Without this, CapMonster solves the Turnstile challenge from its own IP pool while
            // the actual API call goes out via the account's proxy — Cloudflare mints the token
            // for the solving IP, so a different submitting IP gets it rejected downstream as
            // "Captcha verification failed" even though the token itself was solved successfully.
            // (this.proxyDetails was being parsed and logged but never actually sent — dead code.)
            if (this.proxyDetails && this.proxyDetails.proxyAddress) {
                taskPayload.proxyType = this.proxyDetails.proxyType;
                taskPayload.proxyAddress = this.proxyDetails.proxyAddress;
                taskPayload.proxyPort = this.proxyDetails.proxyPort;
                if (this.proxyDetails.proxyLogin) taskPayload.proxyLogin = this.proxyDetails.proxyLogin;
                if (this.proxyDetails.proxyPassword) taskPayload.proxyPassword = this.proxyDetails.proxyPassword;
            }

            const response = await axios.post(`${CAPTCHA_SOLVER_BASE_API}createTask`, {
                clientKey: clientKey,
                task: taskPayload
            });

            if (response.data && response.data.taskId) {
                logger.debug(`[Acc:${this.accountId}] Captcha Task created Id: ${response.data.taskId}`);
                return response.data.taskId;
            } else {
                logger.error(`[Acc:${this.accountId}] Captcha Task creation failed: ${JSON.stringify(response.data)}`);
                return null;
            }
        } catch (err) {
            // err.message can be blank for network-level failures (e.g. Node's happy-eyeballs
            // AggregateError on ECONNREFUSED across multiple IPs) — fall back to err.code/name
            // so a connectivity issue doesn't log as an empty, undiagnosable line.
            const reason = err.response
                ? `HTTP ${err.response.status} ${JSON.stringify(err.response.data)}`
                : (err.message || err.code || err.name || 'Unknown error');
            logger.error(`[Acc:${this.accountId}] Failed to create captcha task: ${reason}`);
            return null;
        }
    }

    async getTaskResult(taskId) {
        try {
            const config = await getConfig();
            const clientKey = config.capmonster_key || this.clientKey;

            for (let i = 0; i < 5; i++) { // Poll up to 5 times
                await new Promise(r => setTimeout(r, 1500));
                const response = await axios.post(`${CAPTCHA_SOLVER_BASE_API}getTaskResult`, {
                    clientKey: clientKey,
                    taskId: taskId
                });

                if (response.data && response.data.status === 'ready') {
                    logger.debug(`[Acc:${this.accountId}] Captcha token retrieved successfully`);
                    return response.data;
                }
            }
            return null;
        } catch (err) {
            const reason = err.response
                ? `HTTP ${err.response.status} ${JSON.stringify(err.response.data)}`
                : (err.message || err.code || err.name || 'Unknown error');
            logger.error(`[Acc:${this.accountId}] Error fetching task result: ${reason}`);
            return null;
        }
    }

    async solveWithPrimaryProvider() {
        try {
            const config = await getConfig();
            const primaryUrl = config.primary_captcha_url;
            if (!primaryUrl) {
                return false;
            }

            logger.info(`[Captcha Pool Acc:${this.accountId}] Attempting to fetch token from Primary Provider...`);
            const response = await axios.get(primaryUrl, { timeout: 5000 });
            if (response.data && response.data.success && response.data.token) {
                const validityMs = response.data.validity_ms || 120000;
                this.pool.push({
                    token: response.data.token,
                    createdAt: Date.now(),
                    expiresAt: Date.now() + validityMs
                });
                logger.info(`✅ [Captcha Pool Acc:${this.accountId}] Token added from Primary Provider — pool: ${this.pool.length}/${this.CAPTCHA_POOL_MAX}`);
                return true;
            } else {
                logger.warn(`[Captcha Pool Acc:${this.accountId}] Primary Provider response: ${response.data.error || 'Unknown error'}`);
                return false;
            }
        } catch (err) {
            logger.error(`[Captcha Pool Acc:${this.accountId}] Failed to fetch from Primary Provider: ${err.message}`);
            return false;
        }
    }

    async solveOneCaptcha() {
        // Try Primary Provider first
        const primarySuccess = await this.solveWithPrimaryProvider();
        if (primarySuccess) {
            return true;
        }

        logger.info(`[Captcha Pool Acc:${this.accountId}] Falling back to CapMonster...`);
        const MAX_RETRY = 3;
        for (let attempt = 1; attempt <= MAX_RETRY; attempt++) {
            logger.info(`[Captcha Pool Acc:${this.accountId}] Solving attempt ${attempt}/${MAX_RETRY} (CapMonster)`);
            const taskId = await this.createTask();
            if (!taskId) continue;

            const solution = await this.getTaskResult(taskId);
            if (solution && solution.status === 'ready' && solution.solution && (solution.solution.token || solution.solution.gRecaptchaResponse)) {
                this.pool.push({
                    token: solution.solution.token || solution.solution.gRecaptchaResponse,
                    createdAt: Date.now(),
                    expiresAt: Date.now() + 120000
                });
                logger.info(`✅ [Captcha Pool Acc:${this.accountId}] Token added from CapMonster — pool: ${this.pool.length}/${this.CAPTCHA_POOL_MAX}`);
                return true;
            }
        }
        return false;
    }

    async fillCaptchaPool() {
        const needed = this.CAPTCHA_POOL_MAX - (this.pool.length + this.filling);
        if (needed <= 0) return;

        logger.info(`🚀 [Captcha Pool Acc:${this.accountId}] Filling ${needed} token(s) in parallel...`);
        const promises = [];
        for (let i = 0; i < needed; i++) {
            this.filling++;
            promises.push(this.solveOneCaptcha().finally(() => { this.filling--; }));
        }
        await Promise.allSettled(promises);
    }

    async getToken() {
        // First check global manual pool
        if (typeof captchaManager !== 'undefined') {
            const manualToken = captchaManager.getGlobalManualToken();
            if (manualToken) {
                logger.info(`⚡ [Captcha Pool Acc:${this.accountId}] Consumed Global Manual Token! (Widget: ${manualToken.widgetId})`);
                return { 
                    token: manualToken.token, 
                    createdAt: manualToken.createdAt, 
                    expiresAt: manualToken.expiresAt,
                    widgetId: manualToken.widgetId
                };
            }
        }

        // Evict stale tokens
        const now = Date.now();
        this.pool = this.pool.filter(e => now < e.expiresAt);

        if (this.pool.length > 0) {
            const entry = this.pool.shift();
            logger.info(`⚡ [Captcha Pool Acc:${this.accountId}] Token consumed instantly — pool remaining: ${this.pool.length}`);
            this.fillCaptchaPool(); // async refilling
            return { token: entry.token, createdAt: entry.createdAt, expiresAt: entry.expiresAt };
        }

        logger.warn(`⏳ [Captcha Pool Acc:${this.accountId}] Pool empty — solving synchronously...`);
        const success = await this.solveOneCaptcha();
        if (success) {
            const entry = this.pool.shift();
            this.fillCaptchaPool();
            return { token: entry.token, createdAt: entry.createdAt, expiresAt: entry.expiresAt };
        }
        return null;
    }

    addManualToken(token) {
        this.pool.unshift({
            token: token,
            createdAt: Date.now(),
            expiresAt: Date.now() + 180000
        });
        logger.info(`✅ [Captcha Pool Acc:${this.accountId}] Manual Token injected — pool: ${this.pool.length}/${this.CAPTCHA_POOL_MAX}`);
    }

    destroy() {
        clearInterval(this.interval);
    }
}

class CaptchaManager {
    constructor(clientKey) {
        this.clientKey = clientKey;
        this.solvers = {}; // solverKey -> CaptchaSolver
        this.globalManualPool = [];
        this.resetCallback = null;
    }

    setResetCallback(cb) {
        this.resetCallback = cb;
    }

    addGlobalManualToken(widgetId, token) {
        // A widget that re-solves replaces its own previous token — keeps the pool
        // free of stale duplicates as widgets auto-refresh on the open solver (~45s).
        this.globalManualPool = this.globalManualPool.filter(e => e.widgetId !== widgetId);
        this.globalManualPool.unshift({
            widgetId,
            token,
            createdAt: Date.now(),
            // Safety net only — the open solver auto-resets each widget every ~45s, so
            // this just guards against serving a token the solver failed to refresh.
            expiresAt: Date.now() + 70000 // ~70s, slightly above the 45s refresh cycle
        });
        logger.info(`✅ [Global Captcha Pool] Manual Token injected from widget ${widgetId} — pool: ${this.globalManualPool.length}`);
    }

    getGlobalManualToken() {
        const now = Date.now();
        // Remove expired and reset them
        const expired = this.globalManualPool.filter(e => now >= e.expiresAt);
        expired.forEach(e => this.resetManualWidget(e.widgetId));
        
        this.globalManualPool = this.globalManualPool.filter(e => now < e.expiresAt);

        if (this.globalManualPool.length > 0) {
            return this.globalManualPool.shift();
        }
        return null;
    }

    resetManualWidget(widgetId) {
        if (this.resetCallback && widgetId) {
            this.resetCallback(widgetId);
        }
    }

    getSolver(accountId, proxyUrl, type, siteKey) {
        // Fallback to defaults to prevent errors if not provided
        const safeType = type || 'TurnstileTask';
        const safeSiteKey = siteKey || '0x4AAAAAACghKkJHL1t7UkuZ';
        const key = `${accountId}_${safeSiteKey}`;

        if (!this.solvers[key]) {
            this.solvers[key] = new CaptchaSolver(this.clientKey, accountId, proxyUrl, safeType, safeSiteKey);
        } else if (proxyUrl !== undefined && this.solvers[key].proxyUrl !== proxyUrl) {
            this.solvers[key].updateProxy(proxyUrl);
        }
        return this.solvers[key];
    }

    clearAllPools() {
        for (const solver of Object.values(this.solvers)) {
            solver.clearPool();
        }
    }

    fillAllPools() {
        for (const solver of Object.values(this.solvers)) {
            solver.fillCaptchaPool();
        }
    }

    getGlobalPoolStatus() {
        let total = 0, filling = 0;
        for (const solver of Object.values(this.solvers)) {
            total += solver.pool.length;
            filling += solver.filling;
        }
        // Count number of active managers
        return { pool: total, max: Object.keys(this.solvers).length * 4, filling };
    }
}

const captchaManager = new CaptchaManager(process.env.CAPMONSTER_KEY);

// Optionally keep captchaSolver mapped to Manager for backward compatibility in some routes, or just export Manager.
module.exports = { captchaManager, CaptchaManager, CaptchaSolver };
