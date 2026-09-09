const { IvacApi } = require('./api');
const { captchaManager } = require('./captcha');
const { OtpClient } = require('./otpListener');
const { logger, updateAccountStatus, saveToken, getStoredToken, insertLog, getAccount, saveRequestId, getSavedRequestId, getAccountFiles, markAccountFileUploaded, markFileConfirmedToday, isFileConfirmedToday } = require('./database');
const fs = require('fs');

const STEP_NAMES = ['Sign In', 'Verify OTP', 'File Upload', 'Reserve Slot', 'Payment Init'];

class BotWorker {
    // Statuses that mean "server busy / transient" — retried indefinitely while the worker runs
    // (transport failure=0, timeouts, 5xx, Cloudflare 52x, rate limits). Shared by _retryCall and
    // the per-file upload loop so both survive busy periods instead of aborting the run.
    static RETRYABLE_STATUSES = new Set([0, 408, 409, 419, 425, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524, 525]);

    constructor(account, proxies, config = {}, io = null, startStep = 0, otpTimeout = 30, otpClient = null) {
        this.account = account;
        this.proxies = proxies;
        this.config = {
            ...config, // pass EVERY config key through (probe_recipe_json, all ep_*_path/ids/headers,
                       // ep_log_source, …) — the typed overrides below win where they exist
            retryDelay: parseInt(config.retryDelay || 5) * 1000,
            successDelay: parseInt(config.successDelay || 0) * 1000,
            paymentInitDelay: parseInt(config.paymentInitDelay || 0) * 1000,
            failDelay: parseInt(config.failDelay || 5) * 1000,
            maxRetry: parseInt(config.maxRetry || 10),
            maxReserveRetry: parseInt(config.maxReserveRetry || 100),
            autoReserveSlot: config.autoReserveSlot !== undefined ? config.autoReserveSlot : '1',
            enable_401_auto: config.enable_401_auto === undefined ? true : parseInt(config.enable_401_auto) === 1,
            ep_signin_url: config.ep_signin_url,
            ep_signin_captchaType: config.ep_signin_captchaType,
            ep_signin_siteKey: config.ep_signin_siteKey,
            ep_signin_encode: parseInt(config.ep_signin_encode || 0),
            ep_signin_ip_count: parseInt(config.ep_signin_ip_count || 1),
            ep_reserve_url: config.ep_reserve_url,
            ep_reserve_slot_id: config.ep_reserve_slot_id,
            ep_reserve_captchaType: config.ep_reserve_captchaType,
            ep_reserve_siteKey: config.ep_reserve_siteKey,
            ep_reserve_encode: parseInt(config.ep_reserve_encode || 0),
            ep_reserve_ip_count: parseInt(config.ep_reserve_ip_count || 1),
            ep_verifyotp_url: config.ep_verifyotp_url,
            ep_verifyotp_ip_count: parseInt(config.ep_verifyotp_ip_count || 1),
            ep_payment_url: config.ep_payment_url,
            ep_payment_captchaType: config.ep_payment_captchaType,
            ep_payment_siteKey: config.ep_payment_siteKey,
            ep_payment_ip_count: parseInt(config.ep_payment_ip_count || 1),
            autoFileUpload: config.autoFileUpload !== undefined ? config.autoFileUpload : '1',
            ep_fileupload_url: config.ep_fileupload_url,
            ep_fileupload_captchaType: config.ep_fileupload_captchaType,
            ep_fileupload_siteKey: config.ep_fileupload_siteKey,
            ep_fileupload_ip_count: parseInt(config.ep_fileupload_ip_count || 1),
            api_timeout: parseInt(config.api_timeout || 30),
            // ─── Cloudflare pacing / anti-429 (per account = per proxy = per bearer token) ───
            cfMinIntervalMs: parseInt(config.cf_min_interval_ms || 700),
            cfBackoffBase: parseInt(config.cf_backoff_base_ms || 2000),
            cfBackoffMax: parseInt(config.cf_backoff_max_ms || 45000),
            cfCacheBuster: parseInt(config.cf_cache_buster || 0),
            fivexxBackoffMs: parseInt(config.fivexx_backoff_ms || 1000),
        };
        this.io = io;
        this.startStep = startStep; // 0=SignIn, 1=VerifyOTP, 2=FileUpload, 3=Reserve, 4=Payment
        this.otpTimeout = parseInt(otpTimeout || 30) * 1000;
        this.proxyIndex = 0;

        let initialProxy = this.proxies.length > 0 ? this.proxies[this.proxyIndex].proxy_url : null;
        this.api = new IvacApi(initialProxy, this.config, this.account.assigned_ip);
        // Hand the full active-proxy list to the API layer so it can rotate one proxy per request.
        this.api.setProxyPool(this.proxies.map(p => p.proxy_url));
        if (this.account.request_id) {
            this.api.setRequestId(this.account.request_id);
            logger.info(`[${this.account.phone}] Initialized with saved Request ID: ${this.account.request_id}`);
        }
        this.api.onLog = (level, msg) => this.log(level, msg);
        // Push the negotiated connection protocol (h1/h2/h3) to the dashboard whenever it changes.
        this.api.onProtocol = (proto) => {
            if (this._lastProto === proto) return;
            this._lastProto = proto;
            if (this.io) this.io.emit('account_protocol', { phone: this.account.phone, protocol: proto });
        };
        this.otpClient = otpClient; // Persistent client injected from server
        this.isRunning = true;
        this.workerAbortController = new AbortController();
        // Set to the Payment step (4) once a manual Reserve succeeds, so the still-running OTP loop
        // converges to Payment on its next iteration. null = no override pending.
        this.manualJumpStep = null;
        // Guards against overlapping manual one-shot actions.
        this._manualBusy = false;
    }

    // Fire a SINGLE Reserve request, in parallel with whatever the worker is currently doing
    // (typically a stuck OTP-verify retry loop). This does NOT interrupt the in-flight request —
    // OTP verify keeps running. On success we flag the worker to advance to Payment.
    async manualReserveOnce() {
        if (!this.isRunning) return { ok: false, error: 'Worker is not running' };
        if (this._manualBusy) return { ok: false, error: 'A manual action is already in progress' };
        this._manualBusy = true;
        try {
            this.log('info', '🖐️ Manual Reserve — fetching captcha for a single attempt...');
            const proxyUrl = this.proxies.length > 0 ? this.proxies[this.proxyIndex].proxy_url : null;
            const solver = captchaManager.getSolver(this.account.id, proxyUrl, this.config.ep_reserve_captchaType, this.config.ep_reserve_siteKey);
            const captchaResult = await solver.getToken();
            if (!captchaResult) {
                this.log('warn', '🖐️ Manual Reserve: no captcha token available.');
                return { ok: false, error: 'No captcha token available' };
            }

            this.log('info', '🖐️ Manual Reserve: sending single request...');
            const response = await this.api.reserveSlot(captchaResult.token, this._reserveDate(), this.workerAbortController);
            if (captchaResult.widgetId) captchaManager.resetManualWidget(captchaResult.widgetId);

            if (response.ok && (response.data.status === 'OK_NEW' || response.data.status === 'OK_EXISTING')) {
                this.log('info', `🎯 Slot Reserved (manual)! ${response.data.message}`);
                this.log('info', `♻️ Status: ${response.data.status} || Reservation ID: ${response.data?.reservationId}`);
                // Upgrade to Payment: the OTP loop will pick this up and let run() proceed to payment.
                this.manualJumpStep = 4;
                this.startStep = 4;
                this.emitStatus('RUNNING');
                return { ok: true };
            }

            const msg = response.data && response.data.message ? response.data.message : `Status ${response.status}`;
            this.log('warn', `🖐️ Manual Reserve failed: ${response.status} - ${msg}`);
            return { ok: false, error: msg };
        } catch (e) {
            this.log('error', `🖐️ Manual Reserve error: ${e.message}`);
            return { ok: false, error: e.message };
        } finally {
            this._manualBusy = false;
        }
    }

    // Fire a SINGLE Payment Init request, in parallel with the running worker. On success it
    // opens the payment browser and stops the worker (same handling as the automatic step).
    async manualPaymentOnce() {
        if (!this.isRunning) return { ok: false, error: 'Worker is not running' };
        if (this._manualBusy) return { ok: false, error: 'A manual action is already in progress' };
        this._manualBusy = true;
        try {
            await this._resolveAppointmentId();
            const captcha = await this._getPaymentCaptchaToken();
            if (captcha.configured && !captcha.token) {
                this.log('warn', '🖐️ Manual Payment: no captcha token available in pool');
                return { ok: false, error: 'No captcha token available in pool' };
            }
            this.log('info', '🖐️ Manual Payment: sending single request...');
            const response = await this.api.initiatePayment(this.appointmentId, captcha.token, this.workerAbortController);

            if (response.ok && response.data.statusCode === 201) {
                this._handlePaymentSuccess(response.data);
                return { ok: true };
            }

            const msg = response.data && response.data.message ? response.data.message : `Status ${response.status}`;
            this.log('warn', `🖐️ Manual Payment failed: ${response.status} - ${msg}`);
            return { ok: false, error: msg };
        } catch (e) {
            this.log('error', `🖐️ Manual Payment error: ${e.message}`);
            return { ok: false, error: e.message };
        } finally {
            this._manualBusy = false;
        }
    }

    updateConfig(newConfig) {
        this.config = {
            ...newConfig, // pass EVERY config key through (probe_recipe_json, all ep_*, …)
            retryDelay: parseInt(newConfig.retryDelay || 5) * 1000,
            successDelay: parseInt(newConfig.successDelay || 0) * 1000,
            paymentInitDelay: parseInt(newConfig.paymentInitDelay || 0) * 1000,
            failDelay: parseInt(newConfig.failDelay || 5) * 1000,
            maxRetry: parseInt(newConfig.maxRetry || 10),
            maxReserveRetry: parseInt(newConfig.maxReserveRetry || 100),
            autoReserveSlot: newConfig.autoReserveSlot !== undefined ? newConfig.autoReserveSlot : '1',
            enable_401_auto: newConfig.enable_401_auto === undefined ? true : parseInt(newConfig.enable_401_auto) === 1,
            ep_signin_url: newConfig.ep_signin_url,
            ep_signin_captchaType: newConfig.ep_signin_captchaType,
            ep_signin_siteKey: newConfig.ep_signin_siteKey,
            ep_signin_encode: parseInt(newConfig.ep_signin_encode || 0),
            ep_signin_ip_count: parseInt(newConfig.ep_signin_ip_count || 1),
            ep_reserve_url: newConfig.ep_reserve_url,
            ep_reserve_slot_id: newConfig.ep_reserve_slot_id,
            ep_reserve_captchaType: newConfig.ep_reserve_captchaType,
            ep_reserve_siteKey: newConfig.ep_reserve_siteKey,
            ep_reserve_encode: parseInt(newConfig.ep_reserve_encode || 0),
            ep_reserve_ip_count: parseInt(newConfig.ep_reserve_ip_count || 1),
            ep_verifyotp_url: newConfig.ep_verifyotp_url,
            ep_verifyotp_ip_count: parseInt(newConfig.ep_verifyotp_ip_count || 1),
            ep_payment_url: newConfig.ep_payment_url,
            ep_payment_captchaType: newConfig.ep_payment_captchaType,
            ep_payment_siteKey: newConfig.ep_payment_siteKey,
            ep_payment_ip_count: parseInt(newConfig.ep_payment_ip_count || 1),
            autoFileUpload: newConfig.autoFileUpload !== undefined ? newConfig.autoFileUpload : '1',
            ep_fileupload_url: newConfig.ep_fileupload_url,
            ep_fileupload_captchaType: newConfig.ep_fileupload_captchaType,
            ep_fileupload_siteKey: newConfig.ep_fileupload_siteKey,
            ep_fileupload_ip_count: parseInt(newConfig.ep_fileupload_ip_count || 1),
            api_timeout: parseInt(newConfig.api_timeout || 30),
            // ─── Cloudflare pacing / anti-429 ───
            cfMinIntervalMs: parseInt(newConfig.cf_min_interval_ms || 700),
            cfBackoffBase: parseInt(newConfig.cf_backoff_base_ms || 2000),
            cfBackoffMax: parseInt(newConfig.cf_backoff_max_ms || 45000),
            cfCacheBuster: parseInt(newConfig.cf_cache_buster || 0),
            fivexxBackoffMs: parseInt(newConfig.fivexx_backoff_ms || 1000),
        };
        if (this.api && typeof this.api.updateConfig === 'function') {
            this.api.updateConfig(this.config);
        }

        this.log('info', '⚙️ Bot configuration dynamically updated!');
    }

    // Emit log to dashboard, winston, and persist to DB
    log(level, message) {
        const time = new Date().toISOString();
        logger[level](`[${this.account.phone}] ${message}`);
        // Persist to DB (fire-and-forget, never throws)
        insertLog(this.account.phone, level.toUpperCase(), message);
        if (this.io) {
            this.io.emit('account_log', { phone: this.account.phone, level: level.toUpperCase(), message, time });
        }
    }

    emitStatus(status) {
        if (this.io) {
            this.io.emit('account_status', {
                phone: this.account.phone,
                status,
                step: this.startStep
            });
        }
    }

    stop() {
        this.isRunning = false;
        if (this.workerAbortController) {
            this.workerAbortController.abort();
        }
        // Don't disconnect the global otpClient here so it can catch late OTPs
        this.log('warn', 'Worker stopped by user.');
    }

    rotateProxy() {
        // Requests already rotate the proxy on every call (api.callApi → rotateToNextProxy).
        // The error-triggered call sites just nudge the same shared pool index forward so a bad
        // proxy is skipped immediately. Delegate to the API layer to keep one source of truth.
        if (this.proxies.length <= 1) return;
        this.api.rotateToNextProxy();
        this.log('info', `Proxy rotated to: ${this.api.proxyUrl}`);
    }

    async sleep(ms) {
        return new Promise(resolve => {
            const timeout = setTimeout(resolve, ms);
            // Check every 500ms if we should stop early
            const interval = setInterval(() => {
                if (!this.isRunning) {
                    clearTimeout(timeout);
                    clearInterval(interval);
                    resolve();
                }
            }, 500);

            // Cleanup interval when timeout finishes naturally
            timeout.unref?.(); // node-specific opt
        });
    }

    async run() {
        while (this.isRunning) {
            const displayStep = STEP_NAMES[this.startStep] || 'Reserve Slot';
            this.log('info', `Starting automation (target step: ${displayStep})`);
            this.emitStatus('RUNNING');
            updateAccountStatus(this.account.id, 'RUNNING').catch(err => console.error(err));

            try {
                if (this.startStep >= 2) {
                    // Try to reuse a stored valid token (avoids full sign-in + OTP)
                    const storedToken = await getStoredToken(this.account.id);
                    if (storedToken) {
                        this.api.setToken(storedToken);
                        this.log('info', `🔑 Reusing stored token (valid for ~14 min). Jumping to: ${displayStep}`);
                    } else {
                        // No valid stored token — must sign in again
                        this.log('info', '⚠️ No valid stored token. Performing fresh Sign In...');
                        this.startStep = 0;
                        await this.signInStep();
                        if (this.startStep <= 1) {
                            await this.verifyOtpStep();
                        }
                    }
                } else if (this.startStep === 1) {
                    // Resume directly at Verify OTP using the stored session from a previous Sign In.
                    const storedToken = await getStoredToken(this.account.id);
                    const requestId = this.account.request_id || await getSavedRequestId(this.account.id);
                    if (storedToken && requestId) {
                        this.api.setToken(storedToken);
                        this.api.setRequestId(requestId);
                        this.skipOtp = false;
                        this.log('info', '🔑 Reusing stored session (token + requestId). Jumping to Verify OTP.');
                        await this.verifyOtpStep();
                    } else {
                        this.log('info', '⚠️ No valid stored session for OTP step. Performing fresh Sign In...');
                        this.startStep = 0;
                        await this.signInStep();
                        if (this.startStep <= 1) {
                            await this.verifyOtpStep();
                        }
                    }
                } else {
                    // Step 0 — always do full sign-in
                    await this.signInStep();
                    if (this.startStep <= 1) {
                        await this.verifyOtpStep();
                    }
                }

                if (!this.isRunning) break;

                // ── File Upload phase (step 2) ──────────────────────────────────────────────
                // IVAC requires documents uploaded before a slot can be reserved. Runs before
                // Reserve so the file is in place when the window opens. Skipped when starting at
                // Reserve/Payment (startStep > 2); already-uploaded files are skipped inside the step.
                if (this.startStep <= 2) {
                    this.startStep = 2;
                    this.emitStatus('RUNNING'); // force UI update
                    if (parseInt(this.config.autoFileUpload) === 1) {
                        await this.fileUploadStep();
                    }
                    if (!this.isRunning) break;
                }

                // ── Reserve phase (step 3) ──────────────────────────────────────────────────
                if (this.startStep <= 3) {
                    const parsedAutoReserve = parseInt(this.config.autoReserveSlot);
                    const isAutoReserve = isNaN(parsedAutoReserve) ? true : parsedAutoReserve === 1; // Default to true if undefined or invalid
                    this.log('debug', `isAutoReserve check: config value=${this.config.autoReserveSlot}, evaluated=${isAutoReserve}`);
                    if (!isAutoReserve) {
                        this.log('info', '🛑 Auto Reserve is OFF. Opening browser with session...');
                        if (this.io) {
                            this.io.emit('auto_open_browser', { accountId: this.account.id });
                        }
                        this.isRunning = false;
                        this.emitStatus('COMPLETED');
                        await updateAccountStatus(this.account.id, 'IDLE');
                        break;
                    }

                    this.startStep = 3;
                    this.emitStatus('RUNNING'); // force UI update

                    await this.reserveSlotStep();

                    // Optional pause before Payment Init. On busy servers Cloudflare can 520 the
                    // payment-init call even though the link was generated (and lost). Waiting a
                    // beat after a successful reserve lets the server settle. 0 = no wait (default).
                    if (this.isRunning && this.config.paymentInitDelay > 0) {
                        this.log('info', `⏳ Waiting ${this.config.paymentInitDelay / 1000}s before Payment Init...`);
                        await this.sleep(this.config.paymentInitDelay);
                    }
                }

                if (!this.isRunning) break;

                // ── Payment phase (step 4) ──────────────────────────────────────────────────
                this.startStep = 4;
                this.emitStatus('RUNNING'); // force UI update

                if (this.isRunning) {
                    await this.initiatePaymentStep();
                }

                if (this.isRunning) {
                    this.log('info', '🎉 All steps completed successfully!');
                    this.emitStatus('COMPLETED');
                    await updateAccountStatus(this.account.id, 'COMPLETED');
                    break;
                }
            } catch (error) {
                if (this.isRunning && error.message === 'SESSION_EXPIRED') {
                    if (this.config.enable_401_auto) {
                        this.log('warn', 'Session expired (401). Restarting from Sign In...');
                        this.startStep = 0;
                        continue;
                    }
                }
                if (this.isRunning) {
                    this.log('error', `🛑 Automation stopped: ${error.message}`);
                    this.emitStatus('FAILED');
                    await updateAccountStatus(this.account.id, 'FAILED');
                }
                break;
            }
        }

        // (Note: Not calling this.otpClient.disconnect() so it stays connected)
        if (!this.isRunning || this.startStep < 4) {
            // If stopped by user or finished but not completed (e.g. error)
            const currentStatus = await getAccount(this.account.id).then(a => a?.status);
            if (currentStatus !== 'COMPLETED') {
                this.emitStatus('IDLE');
                await updateAccountStatus(this.account.id, 'IDLE');
            }
        }

        // The worker has fully exited (stopped or completed) — release the httpcloak session's
        // Go-side connections / QUIC sockets.
        if (this.api && typeof this.api.close === 'function') {
            try { this.api.close(); } catch (e) { }
        }
    }

    async signInStep() {
        let success = false;
        let retryCount = 0;
        let currentCaptchaToken = null;
        let currentCaptchaTokenExpiresAt = 0;
        let currentCaptchaWidgetId = null;

        while (!success && this.isRunning) {
            this.log('info', 'Step: Sign In...');

            if (!currentCaptchaToken) {
                const proxyUrl = this.proxies.length > 0 ? this.proxies[this.proxyIndex].proxy_url : null;
                const solver = captchaManager.getSolver(this.account.id, proxyUrl, this.config.ep_signin_captchaType, this.config.ep_signin_siteKey);

                if (currentCaptchaWidgetId) captchaManager.resetManualWidget(currentCaptchaWidgetId);

                const captchaResult = await solver.getToken();
                if (!captchaResult) {
                    this.log('warn', 'Waiting for captcha token...');
                    await this.sleep(3000);
                    continue;
                }
                currentCaptchaToken = captchaResult.token;
                currentCaptchaTokenExpiresAt = captchaResult.expiresAt || (Date.now() + 120000);
                currentCaptchaWidgetId = captchaResult.widgetId || null;
            }

            // Single request per attempt: one sign-in call. On success → next step; on a
            // failure the per-status handling below decides whether to reuse or refresh the
            // captcha, then we wait retryDelay and loop again. The captcha is reused while valid.
            this.log('info', '🔑 Sign In: sending request...');
            const response = await this.api.signin(this.account.phone, this.account.password, currentCaptchaToken, this.workerAbortController);

            if (response.ok && response.data?.statusCode === 200) {
                this.log('info', '✅ Sign In successful. Token saved.');
                if (currentCaptchaWidgetId) captchaManager.resetManualWidget(currentCaptchaWidgetId);
                const data = response.data.data;
                this.api.setRequestId(data.requestId);
                this.api.setToken(data.accessToken);
                // Persist token to DB so step 2/3 can reuse it within 15-min window
                await saveToken(this.account.id, data.accessToken);
                await saveRequestId(this.account.id, data.requestId);
                if (this.io) {
                    this.io.emit('token_updated', { phone: this.account.phone, token_expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString() });
                }
                success = true;

                if (data.verified) {
                    this.log('info', 'Account already verified. Jumping to Reserve Slot.');
                    this.skipOtp = true;
                } else {
                    this.skipOtp = false;
                }
            } else {
                retryCount++;
                const errBody = response.data && response.data.message ? response.data.message : JSON.stringify(response.data);
                this.log('warn', `Sign In failed (${response.status}): ${errBody}`);

                if ([502, 503, 504].includes(response.status)) {
                    // Server busy / captcha may still be valid — reuse it if it hasn't expired.
                    if (Date.now() < currentCaptchaTokenExpiresAt) {
                        this.log('info', `♻️ ${response.status} Error - Reusing captcha token (valid)`);
                    } else {
                        this.log('warn', `⚠️ ${response.status} Error - Captcha token expired, fetching a new one`);
                        if (currentCaptchaWidgetId) captchaManager.resetManualWidget(currentCaptchaWidgetId);
                        currentCaptchaToken = null;
                        currentCaptchaWidgetId = null;
                    }
                } else {
                    // 403 (captcha rejected/consumed), 400, 429, etc. — get a fresh captcha.
                    if (currentCaptchaWidgetId) captchaManager.resetManualWidget(currentCaptchaWidgetId);
                    currentCaptchaToken = null;
                    currentCaptchaWidgetId = null;
                }

                if ([419].includes(response.status)) {
                    // 429 backoff is handled centrally by the API pacing gate (honors Retry-After).
                    this.log('warn', `⏳ ${response.status} — pacing gate will back this account off before the next request.`);
                    this.rotateProxy(); // no-op with a single proxy; rotates only if multiple are set
                }

                if (retryCount >= this.config.maxRetry) throw new Error('Max retries for Sign In exceeded.');
                await this.sleep(this.config.retryDelay);
            }
        }
    }

    async verifyOtpStep() {
        if (this.skipOtp) return;

        let success = false;

        const doVerifyOtp = async (otpCode, isRetry, otpReceivedTime = 0) => {
            // Single request per attempt: one OTP verify call.
            this.log('info', `📲 OTP Verify: sending request... (Request ID: ${this.api.requestId})`);
            return await this.api.verifyOtp(this.account.phone, otpCode, this.workerAbortController);
        };

        this.log('info', '⏳ Step: Verify OTP — waiting for SMS or Manual Input...');

        let currentOtp = null;
        let otpReceivedTime = 0;
        let isOtpRetry = false;

        while (!success && this.isRunning) {
            // A manual Reserve succeeded (in parallel) → stop looping on OTP and let run()
            // proceed to the Payment step. We never abort the in-flight verify; this is only
            // picked up between verify attempts.
            if (this.manualJumpStep !== null) {
                this.startStep = this.manualJumpStep;
                this.manualJumpStep = null;
                this.log('info', `⏭️ Manual Reserve done — moving on to ${STEP_NAMES[this.startStep]}.`);
                return;
            }
            try {
                if (!currentOtp) {
                    // Wait for OTP (from socket OR manual injection)
                    const otpPromise = this.otpClient.waitForOtp(60 * 1000 * 5);

                    // Make the OTP wait interruptible by the stop button
                    const timeoutPromise = new Promise(resolve => {
                        const checkInterval = setInterval(() => {
                            if (!this.isRunning) { clearInterval(checkInterval); resolve('STOPPED'); }
                        }, 500);
                        // Cleanup interval if OTP arrives first
                        otpPromise.finally(() => clearInterval(checkInterval)).catch(() => { });
                    });

                    const result = await Promise.race([otpPromise, timeoutPromise]);
                    if (result === 'STOPPED') return;

                    currentOtp = result;
                    otpReceivedTime = Date.now();
                    isOtpRetry = false;
                }

                this.log('info', `📱 Processing OTP: ${currentOtp} — verifying...`);

                const response = await doVerifyOtp(currentOtp, isOtpRetry, otpReceivedTime);

                // A manual Reserve completed while this verify was in flight → don't process
                // (or log) this response as OTP progress; let the loop top route to Payment.
                if (this.manualJumpStep !== null) continue;

                if (response.ok && response.data.statusCode === 200) {
                    this.log('info', '✅ OTP Verification successful.');
                    const data = response.data.data;
                    success = true;
                    currentOtp = null;
                } else {
                    this.log('warn', `OTP verification failed (${response.status}). Ret: ${JSON.stringify(response.data)}`);

                    // Session expired → bubble up so the caller can re-sign-in.
                    if (response.status === 401 && this.config.enable_401_auto) throw new Error('SESSION_EXPIRED');

                    // 400 = the server genuinely rejected this code → discard and wait for a NEW OTP.
                    if (response.status === 400) {
                        this.log('warn', 'OTP rejected (400). Waiting for a new OTP...');
                        currentOtp = null;
                        continue;
                    }

                    // 404 "Otp not found" = the OTP was already consumed/verified server-side.
                    // This happens when an earlier attempt actually succeeded at the origin but
                    // Cloudflare reported it back as a 5xx, so we kept retrying a code that's now
                    // gone. Treat it as verified and move straight on to Reserve.
                    if (response.status === 404) {
                        this.log('info', '✅ OTP already verified (404 Otp not found) — proceeding to Reserve.');
                        success = true;
                        currentOtp = null;
                        continue;
                    }

                    // Rate limited → rotate proxy, then keep retrying with the SAME OTP.
                    if ([429, 419].includes(response.status)) this.rotateProxy();

                    // Any other failure = server busy / transient. Retry with the SAME OTP
                    // (do NOT ask for a new one) for as long as it's still valid (5 min).
                    if (Date.now() - otpReceivedTime < 5 * 60 * 1000) {
                        this.log('info', `Server busy (${response.status}). Retrying SAME OTP in ${this.config.retryDelay / 1000}s...`);
                        await this.sleep(this.config.retryDelay);
                        isOtpRetry = true;
                        continue;
                    }

                    // OTP no longer valid → wait for a fresh one.
                    this.log('warn', 'OTP validity expired (5m). Waiting for a new OTP...');
                    currentOtp = null;
                }
            } catch (error) {
                if (error.message === 'SESSION_EXPIRED') throw error;

                // A manual Reserve completed in parallel → let the loop top route to Payment.
                if (this.manualJumpStep !== null) continue;

                // Network/proxy error mid-verify (common when the server is overloaded):
                // keep the OTP and retry with the SAME code while it's still valid.
                this.log('error', `OTP error: ${error.message}`);
                if (currentOtp && Date.now() - otpReceivedTime < 5 * 60 * 1000) {
                    this.log('info', `Retrying SAME OTP in ${this.config.retryDelay / 1000}s...`);
                    await this.sleep(this.config.retryDelay);
                    isOtpRetry = true;
                    continue;
                }
                currentOtp = null; // no OTP yet (or expired) → wait for a new one
            }
        }
    }

    // Pull one Turnstile token from the pool for a file upload. Sent raw as the x-token header.
    // Returns the token string or null if the pool is momentarily empty.
    async _getUploadCaptchaToken() {
        const proxyUrl = this.proxies.length > 0 ? this.proxies[this.proxyIndex].proxy_url : null;
        const solver = captchaManager.getSolver(this.account.id, proxyUrl, this.config.ep_fileupload_captchaType, this.config.ep_fileupload_siteKey);
        const captchaResult = await solver.getToken();
        return captchaResult ? captchaResult.token : null;
    }

    // Best-effort extraction of an applicants list from the /file/overview response, tolerant of
    // the exact shape (which is logged raw on first run for verification). Each entry may carry a
    // web file number and an isPrimary flag.
    _parseOverviewApplicants(data) {
        const root = (data && data.data) ? data.data : data;
        if (!root) return [];
        const arr = Array.isArray(root) ? root
            : (Array.isArray(root.files) ? root.files
                : (Array.isArray(root.applicants) ? root.applicants : []));
        return arr.map((a, i) => ({
            webFileNumber: a.webFileNumber || a.web_file_number || a.fileNumber || a.number || null,
            isPrimary: a.isPrimary !== undefined ? !!a.isPrimary : i === 0,
            // Commission = IVAC mission. Field name varies; the raw overview is logged so the
            // exact key can be confirmed on a live run.
            commissionId: a.commissionId || a.commission_id || a.missionId || a.mission_id || a.highCommissionId || null,
            commissionName: a.commissionName || a.commission_name || a.missionName || a.mission_name || null,
        }));
    }

    // Run a file-phase API call with "keep rolling until it works" retry. When the server is busy
    // (transport failure, 5xx, Cloudflare 52x, 429/419) the call is retried indefinitely while the
    // worker is running — this is what makes overview/create/status/mission survive a busy start
    // instead of failing once and cascading (e.g. "No commission/mission info from overview").
    //   • `fn()` must return the api response `{ ok, status, data }`.
    //   • `until(response)` (optional): a data-readiness check — response was 2xx but the payload
    //     isn't populated yet (e.g. overview has no commission right after upload). Retried a bounded
    //     `maxSoftRetries` times, then returns the response anyway so the caller proceeds best-effort.
    //   • 401 → throws SESSION_EXPIRED (when enabled); 429/419 → rotates proxy.
    // Returns the successful response, the best-effort response after soft retries, or null if the
    // worker was stopped mid-wait.
    async _retryCall(label, fn, { until = null, maxSoftRetries = 8 } = {}) {
        const RETRYABLE = BotWorker.RETRYABLE_STATUSES;
        const delay = this.config.retryDelay || 3000;
        let soft = 0;
        while (this.isRunning) {
            let response = null;
            try {
                response = await fn();
            } catch (e) {
                this.log('warn', `⏳ ${label}: request error (${e.message}) — server busy, retrying in ${delay / 1000}s...`);
                await this.sleep(delay);
                continue;
            }
            const status = response ? response.status : 0;

            if (response && response.ok) {
                if (!until || until(response)) return response;
                // 2xx but data not ready yet (e.g. commission not populated right after upload).
                soft++;
                if (soft >= maxSoftRetries) {
                    this.log('warn', `⚠️ ${label}: data still not ready after ${soft} tries — proceeding with what we have.`);
                    return response;
                }
                this.log('info', `⏳ ${label}: response ok but data not ready yet (${soft}/${maxSoftRetries}) — retrying in ${delay / 1000}s...`);
                await this.sleep(delay);
                continue;
            }

            if (status === 401 && this.config.enable_401_auto) throw new Error('SESSION_EXPIRED');
            if ([429, 419].includes(status)) this.rotateProxy();
            const msg = response && response.data && response.data.message ? response.data.message : `Status ${status}`;

            if (RETRYABLE.has(status)) {
                // Server busy / transient → keep rolling indefinitely while running.
                this.log('warn', `⏳ ${label}: server busy (${status}: ${msg}) — retrying in ${delay / 1000}s...`);
                await this.sleep(delay);
                continue;
            }

            // Genuine error (e.g. 400/403/404) → bounded retry, then give up gracefully so we don't
            // spin forever on something a retry can't fix.
            soft++;
            this.log('warn', `⚠️ ${label} failed (${status}: ${msg}) — attempt ${soft}/${maxSoftRetries}.`);
            if (soft >= maxSoftRetries) return response;
            await this.sleep(delay);
        }
        return null; // worker stopped
    }

    async fileUploadStep() {
        this.log('info', '📎 Step: File Upload...');

        // Files only need uploading once per day. If this account's mission/center confirmation
        // (appointment-booking-config) already succeeded today, the entire file phase — create
        // appointment, upload, mission/center — is done for the day. Skip it and go to Reserve,
        // no matter how many times the account is run again today.
        try {
            if (await isFileConfirmedToday(this.account.id)) {
                this.log('info', '✅ File upload already completed & confirmed today — skipping file phase.');
                return;
            }
        } catch (e) {
            this.log('warn', `⚠️ Could not check today's file-confirmed status: ${e.message}`);
        }

        // The site creates the appointment (POST /appointment, empty body) the moment you enter
        // the booking flow — BEFORE any upload. Without it the upload returns 404 "Appointment
        // not found" (works in a browser only because navigating the pages triggers it). Mirror
        // it here as the first thing in the phase. Best-effort: a benign non-2xx (e.g. it already
        // exists) shouldn't abort — a real problem will surface on the upload itself.
        const appt = await this._retryCall('Create appointment', () => this.api.createAppointment(this.workerAbortController));
        if (appt) this.log('info', `🗓️ Create appointment (${appt.status}): ${JSON.stringify(appt.data)}`);
        if (!this.isRunning) return;

        // Load operator-provided PDFs for this account (ordered by applicant_index).
        let storedFiles = [];
        try {
            storedFiles = await getAccountFiles(this.account.id);
        } catch (e) {
            this.log('warn', `⚠️ Could not load account files: ${e.message}`);
        }
        if (!storedFiles || storedFiles.length === 0) {
            this.log('warn', '⚠️ File Upload is ON but no PDF is stored for this account — skipping upload.');
            return;
        }

        // NOTE: no overview call BEFORE upload — the overview has nothing useful yet (no files are
        // in place, and web file numbers are assigned server-side by the upload itself). We upload
        // straight from the operator's stored file metadata, then fetch the overview ONCE after all
        // files are uploaded (below) for the commission/mission info.

        // "Uploaded today" (not just ever) — a previous day's uploaded_at must not skip today's
        // required re-upload. Same-day interruptions still resume from the next file.
        const alreadyDone = storedFiles.filter(f => f.uploaded_today).length;
        if (alreadyDone > 0) {
            this.log('info', `↩️ Resuming file upload: ${alreadyDone}/${storedFiles.length} already uploaded today — continuing from the rest.`);
        }

        // Upload each stored PDF, one per applicant (in order), using the operator's stored metadata
        // (web file number / isPrimary; first file is primary by default).
        for (let i = 0; i < storedFiles.length && this.isRunning; i++) {
            const f = storedFiles[i];

            // Resume support: skip files already uploaded in a previous run/attempt so a retry
            // continues from the first not-yet-uploaded file instead of re-uploading everything.
            if (f.uploaded_today) {
                this.log('info', `⏭️ ${f.filename} already uploaded today — skipping.`);
                continue;
            }

            const webFileNumber = f.web_file_number || null;
            const isPrimary = (f.is_primary === 1 || f.is_primary === true) ? true : (i === 0);

            let buffer;
            try {
                buffer = fs.readFileSync(f.storage_path);
            } catch (e) {
                this.log('error', `❌ Cannot read stored file ${f.filename} (${f.storage_path}): ${e.message}`);
                throw new Error('File Upload failed: stored PDF missing on disk.');
            }
            if (buffer.length > 10 * 1024 * 1024) {
                throw new Error(`File Upload failed: ${f.filename} exceeds 10 MB.`);
            }

            let uploaded = false;
            let retryCount = 0;
            while (!uploaded && this.isRunning) {
                const token = await this._getUploadCaptchaToken();
                if (!token) {
                    this.log('warn', 'Waiting for file-upload captcha token...');
                    await this.sleep(3000);
                    continue;
                }

                this.log('info', `⬆️ Uploading ${f.filename} (applicant ${i + 1}/${storedFiles.length}, primary=${isPrimary})...`);
                const response = await this.api.uploadFile(
                    { buffer, filename: f.filename, isPrimary, webFileNumber, turnstileToken: token },
                    this.workerAbortController
                );

                // Mirror the site's OWN gate: its upload handler throws unless the response body's
                // `successFlag` is truthy (bundle: `if(!n.data.successFlag) throw new Error(msg)`).
                // HTTP 200 alone means nothing here — the API returns {successFlag:false,message:…}
                // under a 200. The previous catch-all ("2xx with no `error` field") passed exactly
                // those, marking files uploaded that never landed.
                const ud = response.data || {};
                const uploadOk = response.ok && ud.successFlag === true;
                if (uploadOk) {
                    this.log('info', `✅ Uploaded ${f.filename}.`);
                    uploaded = true;
                    // Persist per-file success so a later retry/restart resumes from the next file.
                    try { await markAccountFileUploaded(f.id); } catch (e) { this.log('warn', `Could not mark ${f.filename} uploaded: ${e.message}`); }
                } else if (response.status === 409) {
                    // 409 = the server already has this file (a re-run, or a retry after a response
                    // we never saw). That's a done state, not an error — mark it and move on.
                    // MUST be handled before the RETRYABLE_STATUSES branch below: 409 is in that set,
                    // so otherwise an already-uploaded file retries forever and blocks the queue.
                    this.log('info', `↪️ ${f.filename} already uploaded (409) — skipping to next file.`);
                    uploaded = true;
                    try { await markAccountFileUploaded(f.id); } catch (e) { this.log('warn', `Could not mark ${f.filename} uploaded: ${e.message}`); }
                } else {
                    const errMsg = ud.message
                        || (Array.isArray(ud.errors) && ud.errors.length ? JSON.stringify(ud.errors[0]) : null)
                        || `Status ${response.status}`;
                    // A 2xx that failed the successFlag gate is the silent-rejection case — log the
                    // raw body so the actual reason is visible instead of a bare "failed".
                    if (response.ok) {
                        this.log('warn', `⚠️ ${f.filename}: server returned ${response.status} but successFlag was not true — NOT uploaded. Body: ${JSON.stringify(ud).slice(0, 400)}`);
                    }
                    if (response.status === 401 && this.config.enable_401_auto) throw new Error('SESSION_EXPIRED');
                    if ([429, 419].includes(response.status)) this.rotateProxy();

                    if (BotWorker.RETRYABLE_STATUSES.has(response.status)) {
                        // Server busy / transient (network error, 5xx, Cloudflare 52x, rate limit) →
                        // keep retrying this file indefinitely while running; the next files wait
                        // until this one succeeds. Does NOT count toward maxRetry.
                        this.log('warn', `⏳ Upload ${f.filename}: server busy (${response.status}: ${errMsg}) — retrying in ${this.config.retryDelay / 1000}s...`);
                        await this.sleep(this.config.retryDelay);
                        continue;
                    }

                    // Genuine rejection (e.g. 400/403/404 or a 2xx body error) — a retry may not fix
                    // it, so bound it with maxRetry instead of spinning forever.
                    retryCount++;
                    this.log('warn', `Upload ${f.filename} failed (${response.status}: ${errMsg}) — attempt ${retryCount}/${this.config.maxRetry}.`);
                    if (retryCount >= this.config.maxRetry) throw new Error(`Max retries uploading ${f.filename}.`);
                    await this.sleep(this.config.retryDelay);
                }
            }
        }

        if (!this.isRunning) return;

        // Re-fetch the overview AFTER all uploads. The commission/mission info is only populated
        // once the documents are in place — the pre-upload overview has none, which is why mission
        // confirmation was being skipped ("No commission/mission info from overview"). Prefer the
        // fresh list; fall back to the pre-upload one if the re-fetch fails.
        let finalApplicants = [];
        const ov2 = await this._retryCall(
            'Post-upload overview',
            () => this.api.getFileOverview(this.workerAbortController),
            // Keep rolling until the overview actually carries commission/mission info (the server
            // populates it once the uploaded files are processed) — this is what mission/center needs.
            { until: (r) => this._parseOverviewApplicants(r.data).some(a => a.commissionId || a.commissionName) }
        );
        if (ov2 && ov2.ok) {
            this.log('info', `📋 Post-upload overview (${ov2.status}): ${JSON.stringify(ov2.data)}`);
            const parsed = this._parseOverviewApplicants(ov2.data);
            if (parsed.length) finalApplicants = parsed;
        }
        if (!this.isRunning) return;

        // Mission + IVAC center confirmation (mirrors the site's /appointment/mission page):
        // mission = the PRIMARY applicant's commission; center = the FIRST center for that mission.
        const primary = finalApplicants.find(a => a.isPrimary) || finalApplicants[0] || {};
        await this.fileConfirmationStep(primary.commissionId, primary.commissionName);
        // Check overall file/slot status (informational; also what the site's file page reads).
        const conf = await this._retryCall('File/slot status', () => this.api.getFileConfirmationAndSlotStatus(this.workerAbortController));
        if (conf && conf.ok) this.log('info', `🔓 File status / slot status (${conf.status}): ${JSON.stringify(conf.data)}`);



        this.log('info', '📎 File Upload step complete — proceeding to Reserve.');
    }

    // Submit the IVAC mission + center confirmation that gates Reserve. The site selects the mission
    // from the primary file's commission and the FIRST center returned for that mission, then POSTs
    // { mission: <missionName>, ivacCenter: <centerName> } to appointment-booking-config.
    async fileConfirmationStep(commissionId, commissionName) {
        this.log('info', '🏛️ Step: Mission & Center confirmation...');
        if (!commissionId && !commissionName) {
            this.log('warn', '⚠️ No commission/mission info from overview — skipping mission/center confirmation.');
            return;
        }

        // Resolve the mission NAME (the submit sends the name, not the id).
        let missionName = commissionName;
        if (!missionName && commissionId) {
            const hc = await this._retryCall('High commissions', () => this.api.getHighCommissions(this.workerAbortController));
            if (hc && hc.ok) {
                this.log('info', `🏛️ High commissions (${hc.status}): ${JSON.stringify(hc.data)}`);
                const arr = this._asArray(hc.data);
                const found = arr.find(m => String(m.id) === String(commissionId));
                if (found) missionName = found.missionName || found.name || found.title || null;
            }
        }
        if (!missionName) {
            this.log('warn', '⚠️ Could not resolve mission name — skipping confirmation. Reserve may fail if unconfirmed.');
            return;
        }

        // Center = the FIRST center returned for this mission.
        let centerName = null;
        if (commissionId) {
            const ic = await this._retryCall('IVAC centers', () => this.api.getIvacCenters(commissionId, this.workerAbortController));
            if (ic && ic.ok) {
                this.log('info', `🏢 IVAC centers (${ic.status}): ${JSON.stringify(ic.data)}`);
                const arr = this._asArray(ic.data);
                if (arr.length > 0) centerName = arr[0].centerName || arr[0].name || arr[0].title || null;
            }
        }
        if (!centerName) {
            this.log('warn', '⚠️ Could not resolve IVAC center (first of list) — skipping confirmation.');
            return;
        }

        // Submit the confirmation. Retry on 502/503/504, stop on 500 (same policy as upload).
        let done = false;
        let retryCount = 0;
        while (!done && this.isRunning) {
            this.log('info', `📤 Confirming: mission="${missionName}", center="${centerName}"...`);
            const resp = await this.api.submitFileConfirmation(missionName, centerName, this.workerAbortController);

            // Same successFlag gate the site itself uses (see the upload step). A 2xx alone is NOT
            // success — this used to accept any 200 without an `error` field, which could mark the
            // file phase done for the whole day off a body that actually said it failed.
            const rd = resp.data || {};
            const okBody = rd.successFlag === true;
            if (resp.ok && okBody) {
                this.log('info', '✅ Mission & center confirmed.');
                done = true;
                // Mark the file phase done for today so further runs skip it (files upload once/day).
                try { await markFileConfirmedToday(this.account.id); } catch (e) { this.log('warn', `Could not mark file-confirmed today: ${e.message}`); }
            } else {
                retryCount++;
                const msg = rd.message
                    || (Array.isArray(rd.errors) && rd.errors.length ? JSON.stringify(rd.errors[0]) : null)
                    || `Status ${resp.status}`;
                if (resp.ok) {
                    this.log('warn', `⚠️ Confirmation: server returned ${resp.status} but successFlag was not true — NOT confirmed. Body: ${JSON.stringify(rd).slice(0, 400)}`);
                }
                this.log('warn', `Confirmation failed (${resp.status}): ${msg}`);
                if (resp.status === 401 && this.config.enable_401_auto) throw new Error('SESSION_EXPIRED');
                if (resp.status === 500) throw new Error('File confirmation stopped: server error 500.');
                if ([429, 419].includes(resp.status)) this.rotateProxy();
                if (retryCount >= this.config.maxRetry) throw new Error('Max retries for file confirmation.');
                await this.sleep(this.config.retryDelay);
            }
        }
    }

    // Extract an array from a JSON API response tolerant of { data: [...] } / { data: { data: [...] } }.
    _asArray(data) {
        const root = (data && data.data !== undefined) ? data.data : data;
        if (Array.isArray(root)) return root;
        if (root && Array.isArray(root.data)) return root.data;
        if (root && Array.isArray(root.items)) return root.items;
        return [];
    }

    // The reserve request body now requires the selected appointment date as ISO "YYYY-MM-DD".
    // Source it from the account's target date, tolerant of either a "YYYY-MM-DD" string (as
    // getAccounts returns) or a Date/other value. Returns null when unknown (server may reject).
    _reserveDate() {
        const raw = this.account && this.account.appointment_date;
        if (!raw) return null;
        if (raw instanceof Date) return raw.toISOString().slice(0, 10);
        const s = String(raw);
        const m = s.match(/^(\d{4}-\d{2}-\d{2})/);
        return m ? m[1] : s.slice(0, 10);
    }

    async reserveSlotStep() {
        let success = false;
        let retryCount = 0;
        let currentCaptchaToken = null;
        let currentCaptchaTokenExpiresAt = 0;
        let currentCaptchaWidgetId = null;

        // Reserve now takes a specific appointmentDate. Pull the available dates from
        // get-booking-config and cycle through them: if a date is booked/unavailable, the next
        // attempt tries the next date, looping. After a full pass we re-fetch to refresh
        // availability. (This also caches appointmentId for the payment step.)
        await this._loadReserveDates();
        let dateIdx = 0;

        while (!success && this.isRunning) {
            this.log('info', '🎯 Step: Reserve Slot...');

            if (!currentCaptchaToken) {
                const proxyUrl = this.proxies.length > 0 ? this.proxies[this.proxyIndex].proxy_url : null;
                const solver = captchaManager.getSolver(this.account.id, proxyUrl, this.config.ep_reserve_captchaType, this.config.ep_reserve_siteKey);

                if (currentCaptchaWidgetId) captchaManager.resetManualWidget(currentCaptchaWidgetId);

                const captchaResult = await solver.getToken();
                if (!captchaResult) {
                    await this.sleep(3000);
                    continue;
                }
                currentCaptchaToken = captchaResult.token;
                currentCaptchaTokenExpiresAt = captchaResult.expiresAt || (Date.now() + 120000);
                currentCaptchaWidgetId = captchaResult.widgetId || null;
            }

            // Single request per attempt: one reserve call. On success → done; a 400 (captcha
            // mismatch) or other failure drops through to the handling below, which fetches a
            // fresh captcha and retries after retryDelay.
            const reserveDate = (this.reserveDates && this.reserveDates.length)
                ? this.reserveDates[dateIdx % this.reserveDates.length]
                : this._reserveDate();
            this.log('info', `🎯 Reserve: sending request (date ${reserveDate || 'n/a'})...`);
            const response = await this.api.reserveSlot(currentCaptchaToken, reserveDate, this.workerAbortController);

            if (response.ok) {
                const data = response.data;
                if (data.status === 'OK_NEW' || data.status === 'OK_EXISTING') {
                    this.log('info', `🎯 Slot Reserved! ${data.message}`);
                    this.log('info', `♻️ Status: ${data.status} || Reservation ID: ${data?.reservationId}`);
                    if (currentCaptchaWidgetId) captchaManager.resetManualWidget(currentCaptchaWidgetId);
                    success = true;
                } else {
                    retryCount++;
                    currentCaptchaToken = null; // Clear if not success
                    this.log('warn', `Reserve pending: ${data.message}`);
                }
            } else {
                retryCount++;
                const errorMsg = response.data && response.data.message ? response.data.message : `Status ${response.status}`;
                this.log('warn', `Reserve error: ${response.status} - ${errorMsg}`);

                if ([502, 503, 504].includes(response.status)) {
                    if (Date.now() < currentCaptchaTokenExpiresAt) {
                        this.log('info', `♻️ ${response.status} Error - Reusing captcha token (valid)`);
                    } else {
                        this.log('warn', `⚠️ ${response.status} Error - Captcha token expired, fetching a new one`);
                        if (currentCaptchaWidgetId) captchaManager.resetManualWidget(currentCaptchaWidgetId);
                        currentCaptchaToken = null;
                        currentCaptchaWidgetId = null;
                    }
                } else {
                    if (currentCaptchaWidgetId) captchaManager.resetManualWidget(currentCaptchaWidgetId);
                    currentCaptchaToken = null;
                    currentCaptchaWidgetId = null;
                }

                if (response.status === 401 && this.config.enable_401_auto) throw new Error('SESSION_EXPIRED');

                if ([429, 419].includes(response.status)) {
                    this.rotateProxy();
                }
            }

            if (!success) {
                if (retryCount >= this.config.maxReserveRetry) throw new Error('Max retries for Reserve Slot exceeded.');
                // Move to the next available date for the next attempt (handles "that date is
                // booked"). After cycling through the whole list once, re-fetch booking config so
                // availability stays current. Captcha handling above is independent of the date.
                if (this.reserveDates && this.reserveDates.length > 1) {
                    dateIdx++;
                    if (dateIdx % this.reserveDates.length === 0) await this._loadReserveDates();
                }
                await this.sleep(this.config.retryDelay); // configurable retry delay
            }
        }
    }

    // Load the reserve target dates (and the appointmentId used later for payment) from
    // get-booking-config. Reserve now requires a specific `appointmentDate`, and the site sources
    // the selectable dates from this endpoint's `data.appointmentDate` array. We cache the list so
    // reserveSlotStep can cycle through it, and opportunistically capture `appointmentId` so the
    // payment step doesn't need a second booking-config fetch. Falls back to the account's single
    // configured date when the list is unavailable.
    async _loadReserveDates() {
        try {
            // Retried on a busy server until it returns, and until it actually carries the date list.
            const res = await this._retryCall(
                'Booking config',
                () => this.api.getBookingConfig(this.workerAbortController),
                { until: (r) => { const dd = (r.data && (r.data.data || r.data)) || {}; return Array.isArray(dd.appointmentDate) && dd.appointmentDate.length > 0; } }
            );
            const d = (res && res.ok && res.data) ? (res.data.data || res.data) : null;
            if (d) {
                if (Array.isArray(d.appointmentDate) && d.appointmentDate.length) {
                    this.reserveDates = d.appointmentDate.slice();
                }
                if (d.appointmentId && !this.appointmentId) {
                    this.appointmentId = d.appointmentId;
                    try {
                        const { saveAppointmentId } = require('./database');
                        await saveAppointmentId(this.account.id, this.appointmentId);
                    } catch (_) { /* best-effort cache */ }
                }
                this.log('info', `🗓️ Booking config → dates=${JSON.stringify(this.reserveDates || [])}, appointmentId=${this.appointmentId || '?'}`);
            }
        } catch (e) {
            this.log('warn', `⚠️ Could not load booking-config dates: ${e.message}`);
        }
        if (!this.reserveDates || !this.reserveDates.length) {
            const single = this._reserveDate();
            this.reserveDates = single ? [single] : [];
            if (!this.reserveDates.length) this.log('warn', '⚠️ No reserve dates from booking config and no account date configured.');
        }
    }

    // Resolve the appointmentId needed for payment (cached today → saved → booking config).
    async _resolveAppointmentId() {
        if (this.appointmentId) return;
        try {
            const { getSavedAppointmentId, saveAppointmentId } = require('./database');
            const savedId = await getSavedAppointmentId(this.account.id);
            if (savedId) {
                this.appointmentId = savedId;
                this.log('info', `✅ Loaded cached appointmentId for today: ${this.appointmentId}`);
            } else {
                this.log('info', '🔍 Fetching Booking Config for appointmentId...');
                const configRes = await this.api.getBookingConfig(this.workerAbortController);
                if (configRes.ok && configRes.data?.data?.appointmentId) {
                    this.appointmentId = configRes.data.data.appointmentId;
                    await saveAppointmentId(this.account.id, this.appointmentId);
                    this.log('info', `✅ Found and saved appointmentId: ${this.appointmentId}`);
                } else {
                    this.log('warn', `⚠️ Failed to get appointmentId: ${JSON.stringify(configRes.data)}`);
                }
            }
        } catch (e) {
            this.log('warn', `⚠️ Error fetching appointmentId: ${e.message}`);
        }
    }

    // Handle a successful payment-init response: open the payment browser, notify the
    // dashboard, and stop the worker (shared by the automatic step and the manual one-shot).
    _handlePaymentSuccess(data) {
        console.log(`Mobile: ${this.account.phone}`);
        console.log(data);
        const paymentUrl = data.data?.webview_url || data.data?.redirectGatewayURL;
        this.log('info', `💵 Payment Link generated: ${paymentUrl}`);
        this.log('info', JSON.stringify(data.data));

        // try {
        //     const { spawn } = require('child_process');
        //     const proxyUrlToUse = this.proxies.length > 0 ? this.proxies[this.proxyIndex].proxy_url : 'null';
        //     const windowName = this.account.name || this.account.phone;
        //
        //     global.paymentWindowCount = global.paymentWindowCount || 0;
        //     const count = global.paymentWindowCount++;
        //     const width = 450, height = 700, screenW = 1920;
        //     const cols = Math.max(1, Math.floor((screenW - 50) / 465));
        //     const col = count % cols;
        //     const row = Math.floor(count / cols);
        //     const x = (col * 465) + (row * 40);
        //     const y = (row * 40);
        //
        //     const browserArgs = { proxy: proxyUrlToUse, title: windowName, url: paymentUrl, width, height, x, y, phone: this.account.phone };
        //     const encodedArgs = Buffer.from(JSON.stringify(browserArgs)).toString('base64');
        //     const child = spawn(process.execPath, ['./node_modules/electron/cli.js', '--no-sandbox', '--disable-setuid-sandbox', 'paymentBrowser.js', encodedArgs], {
        //         detached: true,
        //         stdio: 'ignore',
        //         shell: false,
        //         windowsHide: true
        //     });
        //     child.unref();
        //     this.log('info', `🖥️ Opened internal Electron browser for payment`);
        // } catch (e) {
        //     this.log('error', `Failed to open internal browser: ${e.message}`);
        // }

        if (this.io) {
            this.io.emit('payment_link', {
                phone: this.account.phone,
                name: this.account.name || this.account.phone,
                url: paymentUrl
            });
        }
        this.log('info', '🎉 Payment successful! Stopping worker.');
        this.isRunning = false;
        this.emitStatus('COMPLETED');
        updateAccountStatus(this.account.id, 'COMPLETED').catch(() => { });
    }

    // Pull one captcha token from the pool for Payment Init. The token is sent raw as the
    // x-token header (no encryption). Returns { configured, token }:
    //   configured=false → payment captcha isn't set up, proceed without x-token (back-compat)
    //   configured=true, token=null → pool is empty right now, caller should wait and retry
    async _getPaymentCaptchaToken() {
        if (!this.config.ep_payment_captchaType || !this.config.ep_payment_siteKey) {
            return { configured: false, token: null };
        }
        const proxyUrl = this.proxies.length > 0 ? this.proxies[this.proxyIndex].proxy_url : null;
        const solver = captchaManager.getSolver(this.account.id, proxyUrl, this.config.ep_payment_captchaType, this.config.ep_payment_siteKey);
        const captchaResult = await solver.getToken();
        return { configured: true, token: captchaResult ? captchaResult.token : null };
    }

    async initiatePaymentStep() {
        let success = false;
        let retryCount = 0;

        while (!success && this.isRunning) {
            this.log('info', '💳 Step: Payment Init...');
            await this._resolveAppointmentId();

            const captcha = await this._getPaymentCaptchaToken();
            if (captcha.configured && !captcha.token) {
                this.log('warn', 'Waiting for payment captcha token...');
                await this.sleep(3000);
                continue;
            }
            if (captcha.token) this.log('info', '🧩 Payment Init: captcha token attached (x-token).');

            const response = await this.api.initiatePayment(this.appointmentId, captcha.token, this.workerAbortController);

            if (response.ok) {
                const data = response.data;
                if (data.statusCode === 201) {
                    this._handlePaymentSuccess(data);
                    success = true;
                } else {
                    retryCount++;
                    this.log('warn', `Payment Init failed: ${JSON.stringify(data)}`);
                }
            } else {
                retryCount++;
                const errorMsg = response.data && response.data.message ? response.data.message : `Status ${response.status}`;
                this.log('warn', `Payment Init error: ${errorMsg}`);
                if (response.status === 401 && this.config.enable_401_auto) {
                    throw new Error('SESSION_EXPIRED');
                }
                if ([429, 419].includes(response.status)) this.rotateProxy();
            }

            if (!success && this.isRunning) {
                if (retryCount >= this.config.maxRetry) {
                    throw new Error('Max retries for Payment Init exceeded.');
                }
                await this.sleep(this.config.failDelay);
            }
        }
    }
}

module.exports = { BotWorker };
