const { logger } = require('./database');
const { randomUUID } = require('crypto');
const httpcloak = require('httpcloak');

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// Dynamic cipher encryption — keys are fetched from the live website and stored in DB
const { encryptCaptcha } = require('./cipherKeys');

// Map httpcloak's wire protocol token ("h3"/"h2"/"http/1.1") to a human label for logs.
function friendlyProtocol(p) {
    if (!p) return 'unknown';
    const s = String(p).toLowerCase();
    if (s.includes('h3') || s.includes('quic') || s.includes('http/3')) return 'HTTP/3 (QUIC)';
    if (s.includes('h2') || s.includes('http/2')) return 'HTTP/2';
    if (s.includes('h1') || s.includes('http/1')) return 'HTTP/1.1';
    return p;
}

function formatProxyUrl(proxy) {
    if (!proxy) return null;
    
    let protocol = 'http://';
    let raw = proxy;
    
    if (raw.startsWith('socks5://')) {
        protocol = 'socks5://';
        raw = raw.replace('socks5://', '');
    } else if (raw.startsWith('socks5h://')) {
        protocol = 'socks5h://';
        raw = raw.replace('socks5h://', '');
    } else if (raw.startsWith('http://')) {
        protocol = 'http://';
        raw = raw.replace('http://', '');
    } else if (raw.startsWith('https://')) {
        protocol = 'https://';
        raw = raw.replace('https://', '');
    }
    
    if (raw.includes('@')) {
        return protocol + raw;
    }
    
    const parts = raw.split(':');
    if (parts.length === 4) {
        // ip:port:user:pass -> protocol://user:pass@ip:port
        return `${protocol}${parts[2]}:${parts[3]}@${parts[0]}:${parts[1]}`;
    } else if (parts.length === 2) {
        // ip:port -> protocol://ip:port
        return `${protocol}${parts[0]}:${parts[1]}`;
    }
    
    return proxy;
}

class IvacApi {
    constructor(rawProxy, config = {}, assignedIp = null) {
        this.proxyUrl = formatProxyUrl(rawProxy);
        // Pool of proxies this account rotates through, one per request. Seeded from the single
        // initial proxy; botWorker overrides it with the account's full active-proxy list via
        // setProxyPool(). rotateToNextProxy() advances _poolIndex and swaps via setProxy().
        this.proxyPool = this.proxyUrl ? [this.proxyUrl] : [];
        this._poolIndex = 0;
        this.config = config;
        this.assignedIp = assignedIp;
        this.accessToken = null;
        this.requestId = null;
        this.deviceId = this.generateDeviceId();

        // httpcloak session (Go-backed, FFI). Created lazily and rebuilt when the proxy or
        // forced HTTP version changes. One session per account = one TLS/QUIC fingerprint +
        // one cookie jar + one connection pool (matches the per-token / per-proxy model).
        this._session = null;
        this._sessionKey = null;

        // Sticky h3→h2 downgrade. Set when QUIC proves broken on the current proxy (UDP not
        // relayed by the SOCKS5 proxy, or Cloudflare rejecting 0-RTT). Forces h2 until the proxy
        // changes (setProxy() clears it), so a UDP-incapable proxy doesn't dead-end on every call.
        this._h3BrokenOnProxy = false;

        // ─── Cloudflare pacing gate (per account = per proxy = per bearer token) ───────────
        // IVAC rate-limits by bearer token AND by IP. Each account owns one proxy + one token,
        // so the only effective control is to PACE this account's own requests and BACK OFF
        // hard on 429. All steps funnel through callApi(), so gating here throttles the whole
        // worker centrally.
        this._lastReqStart = 0;       // timestamp of the previous request start (min-interval spacing)
        this._penaltyUntil = 0;       // hard pause-until set on 429 (honors Retry-After)
        this._consecutive429 = 0;     // for exponential backoff growth
        this._gateChain = Promise.resolve(); // serializes start-spacing decisions
        this._refreshCfTuning();
    }

    _refreshCfTuning() {
        const c = this.config || {};
        // Worker passes camelCase; fall back to raw DB keys and finally to safe defaults.
        this.cfMinIntervalMs = parseInt(c.cfMinIntervalMs ?? c.cf_min_interval_ms ?? 700) || 0;
        this.cfBackoffBase = parseInt(c.cfBackoffBase ?? c.cf_backoff_base_ms ?? 2000) || 2000;
        this.cfBackoffMax = parseInt(c.cfBackoffMax ?? c.cf_backoff_max_ms ?? 45000) || 45000;
        this.cfCacheBuster = parseInt(c.cfCacheBuster ?? c.cf_cache_buster ?? 0) === 1;
    }

    // HTTP version httpcloak should use.
    //   - Explicit "h1" | "h2" | "h3" → forced as-is.
    //   - "auto" (default) → SMART pick by proxy type, because httpcloak's own "auto" almost
    //     always settles on h2 (TCP wins the race; it never upgrades to h3 on its own). So to
    //     actually get HTTP/3 we force "h3" wherever QUIC can travel — i.e. a direct connection
    //     or a SOCKS5/MASQUE (UDP-capable) proxy — and fall back to "h2" only behind a plain
    //     http:// proxy, which can't tunnel QUIC (UDP) through its CONNECT path.
    _httpVersion() {
        const v = String(this.config.http_version || this.config.hc_http_version || 'auto').toLowerCase();
        if (v === 'h1' || v === 'h2') return v;        // explicit non-QUIC choice always wins
        // For 'h3' or 'auto': if h3 already failed on this proxy, stay on h2 until it rotates.
        if (this._h3BrokenOnProxy) return 'h2';
        if (v === 'h3') return 'h3';                   // explicitly forced (and not yet proven broken)
        const p = (this.proxyUrl || '').toLowerCase();
        if (p.startsWith('http://') || p.startsWith('https://')) return 'h2'; // http proxy → no QUIC
        return 'h3'; // direct or socks5 → try HTTP/3 (auto-falls back to h2 if QUIC can't get through)
    }

    // True for QUIC/HTTP3 transport failures we can recover from by retrying on h2: the SOCKS5
    // proxy isn't relaying UDP (handshake/frame timeouts) or Cloudflare rejected 0-RTT resumption.
    _isH3TransportError(msg) {
        const m = String(msg || '').toLowerCase();
        return m.includes('[h3]') || m.includes('http3') || m.includes('quic') ||
               m.includes('0-rtt') || m.includes('no recent network activity');
    }

    _preset() {
        // Keep the fingerprint current — a stale Chrome version (UA + JA3/JA4) slowly raises the
        // Cloudflare bot score. Bump the default as the library ships newer presets.
        return this.config.hc_preset || 'chrome-149-windows';
    }

    // Lazily build (or rebuild) the httpcloak session. Rebuilds only when the proxy or the
    // forced HTTP version actually changes — otherwise the warm connection pool is reused.
    _getSession() {
        const key = `${this.proxyUrl || 'direct'}|${this._httpVersion()}|${this._preset()}`;
        if (this._session && this._sessionKey === key) return this._session;

        if (this._session) { try { this._session.close(); } catch (e) { } }

        const opts = {
            preset: this._preset(),
            httpVersion: this._httpVersion(),
            timeout: parseInt(this.config.api_timeout) || 180, // seconds
            verify: false,            // matches the old rejectUnauthorized:false behavior
            // QUIC idle timeout. Keep this MODEST: holding an idle h3 connection open longer than the
            // proxy/NAT keeps the UDP flow alive means we reuse a connection that's already dead →
            // "no recent network activity" / "0-RTT rejected" hangs that only a restart cleared. 60s
            // matches typical NAT UDP timeouts; the h3 self-heal in callApi() rebuilds anything that
            // still goes stale. Override with hc_quic_idle if your proxies hold UDP flows longer.
            quicIdleTimeout: parseInt(this.config.hc_quic_idle ?? 60) || 60,
        };

        // ─── Cloudflare TLS-fidelity options ───────────────────────────────────────────────
        // api.ivacbd.com sits behind Cloudflare. Real Chrome encrypts its SNI to Cloudflare via
        // Encrypted Client Hello; sending a plaintext SNI is a "not-a-real-browser" tell. Pointing
        // ECH at cloudflare-ech.com makes the handshake match a genuine Chrome→Cloudflare client.
        // (Works through SOCKS5 too; falls back to plaintext SNI if the ECH lookup fails.)
        // Disable with config hc_ech=0 if a locked-down network blocks the HTTPS-RR DNS lookup.
        if (parseInt(this.config.hc_ech ?? 1) === 1) {
            opts.echConfigDomain = this.config.hc_ech_domain || 'cloudflare-ech.com';
        }

        // Prefer IPv4 so a host with broken/half-open IPv6 doesn't stall on a dead AAAA route
        // before falling back — fewer transport timeouts. Proxies are v4 anyway. Override hc_prefer_ipv4=0.
        if (parseInt(this.config.hc_prefer_ipv4 ?? 1) === 1) {
            opts.preferIpv4 = true;
        }

        if (this.proxyUrl) opts.proxy = this.proxyUrl;

        this._session = new httpcloak.Session(opts);
        this._sessionKey = key;
        return this._session;
    }

    // Acquire a send slot: wait out any 429 penalty, then enforce min-interval spacing.
    // Serialized through _gateChain so concurrent slots can't all slip past the spacing check.
    async _gate(abortController) {
        if (!this.cfMinIntervalMs && !this._penaltyUntil) return;
        const isAborted = () => !!(abortController && abortController.signal && abortController.signal.aborted);
        const run = this._gateChain.then(async () => {
            // Honor an active penalty window (set by a prior 429). Sleep in ≤1s slices and bail
            // the moment the request is aborted (worker stopped) — otherwise a request waiting out
            // a long penalty would be stuck here and block the worker from shutting down.
            let waitFor = this._penaltyUntil - Date.now();
            while (waitFor > 0) {
                if (isAborted()) return;
                await sleep(Math.min(waitFor, 1000));
                waitFor = this._penaltyUntil - Date.now();
            }
            if (isAborted()) return;
            // Enforce minimum spacing between request starts.
            const gap = this.cfMinIntervalMs - (Date.now() - this._lastReqStart);
            if (gap > 0) await sleep(gap);
            this._lastReqStart = Date.now();
        });
        this._gateChain = run.catch(() => { }); // never let the chain break
        return run;
    }

    // Record the rate-limit outcome of a request and adjust the penalty window.
    _noteOutcome(status, headers) {
        if (status === 429) {
            this._consecutive429++;
            let ms = 0;
            const ra = headers && (headers['retry-after'] || headers['Retry-After']);
            if (ra) {
                const secs = parseInt(ra, 10);
                if (!isNaN(secs)) ms = secs * 1000;
                else { const d = Date.parse(ra); if (!isNaN(d)) ms = Math.max(0, d - Date.now()); }
            }
            if (!ms) {
                ms = Math.min(this.cfBackoffBase * Math.pow(2, this._consecutive429 - 1), this.cfBackoffMax);
            }
            ms += Math.floor(Math.random() * 400); // jitter
            // Cap the freeze at cfBackoffMax. IVAC sometimes returns Retry-After: 600 (10 min) —
            // honoring that literally makes the whole account look dead. Better to back off a
            // bounded amount and keep moving.
            const requestedMs = ms;
            ms = Math.min(ms, this.cfBackoffMax);
            this._penaltyUntil = Math.max(this._penaltyUntil, Date.now() + ms);
            const ray = headers && (headers['cf-ray'] || headers['CF-RAY']);
            const capNote = requestedMs > ms + 500 ? ` (server asked ${Math.round(requestedMs / 1000)}s — capped)` : '';
            if (this.onLog) this.onLog('warn', `🐢 429 rate-limited — pausing this account ${Math.round(ms / 1000)}s (x${this._consecutive429})${capNote}${ray ? ` [cf-ray ${ray}]` : ''}`);
        } else if (status >= 200 && status < 300) {
            this._consecutive429 = 0;
        }
    }

    generateDeviceId() {
        const chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        let result = '';
        for (let i = 0; i < 20; i++) {
            result += chars[Math.floor(Math.random() * chars.length)];
        }
        return result;
    }

    updateConfig(config) {
        this.config = config;
        this._recipeCache = undefined; // re-read probe_recipe_json from the new config on next use
        this._refreshCfTuning();
        // _getSession() rebuilds automatically if preset / http version changed.
    }

    setProxy(rawProxy) {
        const newProxy = formatProxyUrl(rawProxy);
        if (newProxy === this.proxyUrl) return;
        this.proxyUrl = newProxy;
        // A different proxy may well carry QUIC — clear the sticky h3 downgrade so the new one
        // gets a fresh h3 attempt. If we were downgraded, the live session is h2 and the new
        // desired version is h3, so the cheap live-swap would leave key/transport mismatched —
        // force a full rebuild in that case instead.
        const wasDowngraded = this._h3BrokenOnProxy;
        this._h3BrokenOnProxy = false;
        if (this._session && !wasDowngraded) {
            // Apply to the live session without tearing it down. setProxy() closes existing
            // connections and reconnects through the new proxy (both TCP and UDP/QUIC).
            try {
                this._session.setProxy(this.proxyUrl || '');
                this._sessionKey = `${this.proxyUrl || 'direct'}|${this._httpVersion()}|${this._preset()}`;
            } catch (e) {
                // Fall back to a full rebuild on next request.
                this._session = null;
                this._sessionKey = null;
            }
        } else if (this._session) {
            // Was h2-downgraded — rebuild so the new proxy can try h3 cleanly.
            try { this._session.close(); } catch (e) { }
            this._session = null;
            this._sessionKey = null;
        }
        logger.debug(`Proxy updated to ${this.proxyUrl}`);
    }

    // Replace the rotation pool with the account's active proxies. Normalizes each entry the same
    // way the constructor/setProxy do, drops empties, and points the live proxy at the first one.
    setProxyPool(rawProxies) {
        const pool = (rawProxies || []).map(p => formatProxyUrl(p)).filter(Boolean);
        this.proxyPool = pool;
        this._poolIndex = 0;
        if (pool.length > 0) this.setProxy(pool[0]);
    }

    // Advance to the next proxy in the pool (called before each request). No-op with 0 or 1 proxy.
    rotateToNextProxy() {
        if (this.proxyPool.length <= 1) return;
        this._poolIndex = (this._poolIndex + 1) % this.proxyPool.length;
        this.setProxy(this.proxyPool[this._poolIndex]);
    }

    setToken(token) {
        this.accessToken = token;
    }

    setRequestId(requestId) {
        this.requestId = requestId;
    }

    close() {
        if (this._session) { try { this._session.close(); } catch (e) { } }
        this._session = null;
        this._sessionKey = null;
    }

    /**
     * Single request through httpcloak. Never throws — always resolves to
     * { ok, status, data, headers, ipUsed, reqTime, protocol }. A transport
     * failure (DNS/TCP/TLS/QUIC/timeout) or an abort comes back as status 0,
     * exactly like the old got-based contract so botWorker logic is unchanged.
     *
     * @param {number} _ipCount  retained for signature compatibility (origin-IP fan-out removed)
     */
    async callApi(endpoint, method = 'GET', data = null, customBaseUrl = null, _ipCount = 1, abortController = null, _h3Attempt = 0, extraHeaders = null, multipart = null) {
        // Per-request proxy rotation: switch to the next proxy in the pool on every fresh call.
        // Guarded to the first attempt so the h3→h2 self-heal retries below (which recurse with
        // _h3Attempt > 0) don't rotate the proxy out from under a recovery in progress.
        if (_h3Attempt === 0) this.rotateToNextProxy();

        let busteredEndpoint = endpoint;
        if (this.cfCacheBuster && endpoint) {
            const _t = Date.now();
            const _r = randomUUID();
            const separator = endpoint.includes('?') ? '&' : '?';
            busteredEndpoint = `${endpoint}${separator}_t=${_t}&_r=${_r}`;
        }

        const url = (customBaseUrl || 'https://api.ivacbd.com/iams/api/') + busteredEndpoint;

        // Functional headers only — the preset supplies user-agent, sec-ch-ua, sec-fetch-*,
        // accept-language ordering, etc. at the right positions in the header list.
        const headers = {
            'accept': 'application/json, text/plain, */*',
            'content-type': 'application/json;charset=UTF-8',
            'accept-language': 'en-US,en;q=0.9',
            'origin': 'https://appointment.ivacbd.com',
            'referer': 'https://appointment.ivacbd.com/',
            'x-device-id': this.deviceId,
        };
        if (this.cfCacheBuster) {
            headers['cache-control'] = 'no-cache, no-store, must-revalidate';
            headers['pragma'] = 'no-cache';
            headers['expires'] = '0';
        }
        if (this.accessToken) {
            headers['authorization'] = `Bearer ${this.accessToken}`;
        }
        // Per-call functional headers (e.g. payment-init captcha token via x-token). Raw value,
        // no encryption — merged last so a caller can override defaults if ever needed.
        if (extraHeaders) {
            Object.assign(headers, extraHeaders);
        }

        const options = { headers };
        if (multipart) {
            // httpcloak builds the multipart body + sets its own multipart Content-Type (with the
            // boundary). Drop our JSON content-type so we don't send two conflicting headers.
            delete headers['content-type'];
            if (multipart.formData) options.data = multipart.formData;
            if (multipart.files) options.files = multipart.files;
        } else if (data) {
            options.json = typeof data === 'string' ? JSON.parse(data) : data;
        }
        if (abortController && abortController.signal) {
            options.signal = abortController.signal;
        }

        // Cap every h3 request with a fail-fast timeout. A pooled QUIC connection that the proxy/NAT
        // silently dropped otherwise hangs ~90s ("no recent network activity") before erroring; with
        // the cap a stale/dead conn surfaces in seconds and the self-heal below rebuilds it. Real API
        // calls return in 1-3s, so 15s is generous headroom. Raise via hc_h3_timeout_ms if needed.
        if (this._httpVersion() === 'h3') {
            options.timeout = parseInt(this.config.hc_h3_timeout_ms ?? 15000) || 15000; // ms
        }

        // Pace this account's outgoing requests (min-interval spacing + honor any 429 penalty).
        // Pass the abortController so a stopped worker isn't stuck waiting out a penalty here.
        await this._gate(abortController);

        const ipUsed = this.proxyUrl || 'Direct';
        const startTime = Date.now();
        try {
            const session = this._getSession();
            logger.debug(`[API] ${method} ${endpoint} via ${ipUsed} | token=${this.accessToken ? this.accessToken.substring(0, 20) + '...' : 'NONE'}`);

            const response = await session.request(method, url, options);
            const reqTime = Date.now() - startTime;

            let responseData = response.text;
            if (typeof responseData === 'string') {
                try {
                    const cleanedStr = responseData.replace(/disabled"\.\s+Please/g, 'disabled. Please');
                    responseData = JSON.parse(cleanedStr);
                } catch (e) { }
            }

            const status = response.statusCode;
            this._noteOutcome(status, response.headers);

            // Surface the actual negotiated connection (h1/h2/h3) — to the log stream and, via the
            // onProtocol hook, to the dashboard badge so you can see how each account reached the server.
            this.lastProtocol = response.protocol;
            if (this.onProtocol) this.onProtocol(response.protocol);

            if (this.onLog) {
                this.onLog('info', `📡 [${method}] /${endpoint || 'warmup'} via ${ipUsed} (${reqTime}ms, ${friendlyProtocol(response.protocol)})`);
            }

            return {
                ok: status >= 200 && status < 300,
                status,
                data: responseData,
                body: response.body, // raw Buffer — binary endpoints (invoice PDF) read this, not `data`
                headers: response.headers,
                ipUsed,
                reqTime,
                protocol: response.protocol
            };
        } catch (error) {
            const reqTime = Date.now() - startTime;

            // Aborted by the worker (stop button / step cancel).
            if ((error && (error.name === 'AbortError')) || (abortController && abortController.signal && abortController.signal.aborted)) {
                return { ok: false, status: 0, data: 'ABORTED', ipUsed, reqTime, message: 'Request aborted' };
            }

            // Transport-level failure (DNS / TCP / TLS / QUIC / timeout) → status 0 so the
            // worker treats it like a retryable server error.
            const msg = (error && error.message) ? error.message : String(error);

            // ─── h3 self-heal: rebuild the connection first, downgrade only as last resort ──────
            // "Restarting the server fixes it" = the pooled QUIC connection went stale (proxy/NAT
            // dropped the idle UDP flow, or Cloudflare rejected 0-RTT on a half-dead conn) and was
            // being reused. So on an h3 transport error we mimic the restart at session scope:
            //   Tier 1 (attempt 0): hard-close the session and rebuild — a FRESH QUIC handshake with
            //                       no reused 0-RTT ticket — then retry on h3. Fixes the stale-conn case.
            //   Tier 2 (attempt 1): if even a fresh h3 connection fails, the proxy genuinely can't carry
            //                       QUIC → mark it h3-broken (sticky until rotation) and retry on h2.
            if (this._httpVersion() === 'h3' && this._isH3TransportError(msg)) {
                if (_h3Attempt === 0) {
                    try { if (this._session) this._session.close(); } catch (e) { }
                    this._session = null; this._sessionKey = null; // forces a clean rebuild in _getSession()
                    if (this.onLog) this.onLog('warn', `♻️ HTTP/3 connection stale via ${ipUsed} — reconnecting (fresh QUIC) and retrying.`);
                    logger.warn(`h3 fresh-reconnect on ${this.proxyUrl || 'Direct'}: ${msg.substring(0, 120)}`);
                    return await this.callApi(endpoint, method, data, customBaseUrl, _ipCount, abortController, 1, extraHeaders);
                }
                if (_h3Attempt === 1 && !this._h3BrokenOnProxy) {
                    this._h3BrokenOnProxy = true; // _getSession() now resolves to h2 (key changes)
                    if (this.onLog) this.onLog('warn', `⚠️ HTTP/3 still failing via ${ipUsed} after reconnect — falling back to HTTP/2.`);
                    logger.warn(`h3→h2 downgrade on ${this.proxyUrl || 'Direct'}: ${msg.substring(0, 120)}`);
                    return await this.callApi(endpoint, method, data, customBaseUrl, _ipCount, abortController, 2, extraHeaders);
                }
            }

            this._noteOutcome(0, undefined);
            logger.warn(`API transport error on ${url}: ${msg.substring(0, 150)}`);
            if (this.onLog) {
                this.onLog('warn', `❌ [${method}] /${endpoint || 'warmup'} via ${ipUsed} (${reqTime}ms) - ${msg.substring(0, 200)}`);
            }
            return { ok: false, status: 0, data: msg, ipUsed, reqTime };
        }
    }

    // ─── Generic recipe executor ─────────────────────────────────────────────────
    // The Bundle Probe learns each step's FULL request off the live bundle and stores it as
    // `probe_recipe_json` (see probeMapper.js). Replaying that recipe — every header name+value
    // and body field, verbatim, substituting only the per-account/per-request dynamics — is what
    // makes ANY frontend change (a reshaped url, a renamed/added/removed header, a renamed body
    // field) auto-adjust. Each step below tries this first and falls back to its hardcoded path.
    _getRecipe() {
        if (this._recipeCache !== undefined) return this._recipeCache;
        let r = null;
        try { if (this.config.probe_recipe_json) r = JSON.parse(this.config.probe_recipe_json); } catch (e) { r = null; }
        this._recipeCache = r;
        return r;
    }

    // Build { endpoint, method, body, customBaseUrl, extraHeaders } for `step` from the recipe,
    // or null if there's no recipe for it. `inputs` supplies the runtime dynamics.
    _buildRecipeRequest(step, inputs = {}) {
        const recipe = this._getRecipe();
        const s = recipe && recipe.steps && recipe.steps[step];
        if (!s || !s.path) { this._logSource(step, false); return null; }

        const extraHeaders = {};
        for (const h of (s.headers || [])) {
            if ('value' in h) { extraHeaders[h.name] = h.value; continue; }
            if (h.role === 'tokenHeader') { if (inputs.turnstileToken != null) extraHeaders[h.name] = inputs.turnstileToken; }
            else if (h.role === 'deviceId') { extraHeaders[h.name] = inputs.deviceId || this.deviceId; }
            // role 'bearer' → callApi sets Authorization from this.accessToken; nothing to do here.
        }

        const fill = (role) => {
            switch (role) {
                case 'phone': return inputs.phone;
                case 'password': return inputs.password;
                case 'otpCode': return inputs.otpCode;
                case 'requestId': return inputs.requestId != null ? inputs.requestId : this.requestId;
                case 'appointmentId': return inputs.appointmentId;
                case 'appointmentDate': return inputs.appointmentDate;
                case 'mission': return inputs.mission;
                case 'ivacCenter': return inputs.ivacCenter;
                case 'missionId': return inputs.missionId;
                case 'bearer': return inputs.bearer != null ? inputs.bearer : this.accessToken;
                case 'captcha': return inputs.captcha; // already encode-processed by the caller
                default: return undefined;
            }
        };

        // Substitute any {placeholder} path params (e.g. ivac-centers/{missionId}) at runtime.
        const endpoint = String(s.path).replace(/\{(\w+)\}/g, (m, k) => {
            const v = fill(k);
            return v !== undefined && v !== null ? encodeURIComponent(v) : m;
        });

        let body = null;
        if (s.body && s.body.type === 'json') {
            body = {};
            for (const e of (s.body.entries || [])) {
                if ('value' in e) { body[e.key] = e.value; continue; }
                const v = fill(e.role);
                if (v !== undefined) body[e.key] = v; // omit unresolved optionals (e.g. no appointmentDate)
            }
        }

        this._logSource(step, true, endpoint);
        return {
            endpoint,
            method: s.method || 'POST',
            body,
            customBaseUrl: s.baseUrl || null,
            extraHeaders: Object.keys(extraHeaders).length ? extraHeaders : null,
        };
    }

    // Log whether a step's request was built from the learned RECIPE or the hardcoded DEFAULT,
    // so you can confirm at a glance which path each call took. Gated by config `ep_log_source`
    // (default on); logs to the dashboard (this.onLog) and the server log.
    _logSource(step, fromRecipe, endpoint) {
        if (parseInt(this.config.ep_log_source ?? '1') === 0) return;
        const msg = fromRecipe
            ? `🧩 [recipe] ${step} → ${endpoint}`
            : `📌 [default] ${step} — no recipe, using hardcoded path`;
        try { if (this.onLog) this.onLog('info', msg); } catch (e) { /* ignore */ }
        logger.info(`[ReqSource] ${msg}`);
    }

    // Convenience: run a step straight from the recipe (for the plain GET/POST endpoints that
    // have no custom body-building). Returns the callApi result, or null when there's no recipe
    // for `step` so the caller can fall back to its hardcoded path.
    async _tryRecipe(step, inputs, ipCount, abortController) {

        const built = this._buildRecipeRequest(step, inputs || {});
        if (!built) return null;
        return await this.callApi(built.endpoint, built.method, built.body, built.customBaseUrl, ipCount, abortController, 0, built.extraHeaders);
    }

    async signin(phone, password, captchaToken, abortController = null) {
        let processedToken = captchaToken;
        if (parseInt(this.config.ep_signin_encode) === 1 && captchaToken) {
            processedToken = encryptCaptcha(captchaToken, 'signin');
        }
        const body = { phone, password, c: processedToken };
        // v23-sign-in rejects requests that lack the site's static "navigation state" header (the
        // browser sends it on every login POST; without it the API 500s). It's a fixed UUID baked
        // into the frontend bundle — kept in config so it can be updated if the site rotates it.
        // NOTE: the version segment rotates (…was v12, bundle mrx52llu-V6dyI3yh.js as of 2026-07-23
        // is v23). If sign-in starts 404-ing, re-check `/auth/vNN-sign-in` in the current bundle.
        // Full recipe replay first (auto-adjusts any url/header/body change); fall back to hardcoded.
        const built = this._buildRecipeRequest('signin', { phone, password, captcha: processedToken });
        if (built) {
            return await this.callApi(built.endpoint, built.method, built.body, built.customBaseUrl, parseInt(this.config.ep_signin_ip_count) || 1, abortController, 0, built.extraHeaders);
        }
        const navState = this.config.ep_signin_nav_state || '80d51dc5-af20-46fa-a7bb-e6a8f3f80065';
        const extraHeaders = { 'x-sec-navigation-state': navState };
        // Path is version-suffixed (…v23) and rotates; the Bundle Probe writes ep_signin_path so
        // a rotation auto-adjusts without a code edit. Hardcoded value stays as the fallback.
        const signinPath = this.config.ep_signin_path || 'v1/auth/v23-sign-in';
        return await this.callApi(signinPath, 'POST', body, this.config.ep_signin_url, parseInt(this.config.ep_signin_ip_count) || 1, abortController, 0, extraHeaders);
    }

    async verifyOtp(phone, otpCode, abortController = null) {
        const body = {
            requestId: this.requestId,
            phone,
            code: otpCode,
            otpChannel: "PHONE"
        };
        const built = this._buildRecipeRequest('verifyOtp', { phone, otpCode, requestId: this.requestId });
        if (built) {
            return await this.callApi(built.endpoint, built.method, built.body, built.customBaseUrl, parseInt(this.config.ep_verifyotp_ip_count) || 1, abortController);
        }
        const otpPath = this.config.ep_verifyotp_path || 'v1/otp/verifySigninOtp';
        return await this.callApi(otpPath, 'POST', body, this.config.ep_verifyotp_url, parseInt(this.config.ep_verifyotp_ip_count) || 1, abortController);
    }

    async reserveSlot(captchaToken, appointmentDate = null, abortController = null) {
        let processedToken = captchaToken;
        if (parseInt(this.config.ep_reserve_encode) === 1 && captchaToken) {
            processedToken = encryptCaptcha(captchaToken, 'reserve');
        }
        // The site's reserve request changed: the body now carries the selected appointment date
        // (ISO "YYYY-MM-DD") alongside the captcha field `c` — i.e. { c, appointmentDate }.
        // Full recipe replay first — the reserve URL SHAPE (not just the slotId) and its headers
        // auto-adjust here; fall back to the hardcoded template below.
        const builtReserve = this._buildRecipeRequest('reserve', { captcha: processedToken, ...(appointmentDate ? { appointmentDate } : {}) });
        if (builtReserve) {
            return await this.callApi(builtReserve.endpoint, builtReserve.method, builtReserve.body, builtReserve.customBaseUrl, parseInt(this.config.ep_reserve_ip_count) || 1, abortController, 0, builtReserve.extraHeaders);
        }
        const body = { c: processedToken };
        if (appointmentDate) body.appointmentDate = appointmentDate;
        // Endpoint changed too: the old `v1/slots/reserveSlot` now returns 403 "Endpoint not
        // allowed". Reserve is now `v1/slots/<slotId>/reserve-slot` where slotId is the service id
        // baked into the site bundle. Kept in config (ep_reserve_slot_id) so it can be updated
        // without a code change if the site rotates it.
        const slotId = this.config.ep_reserve_slot_id || '54ea9f13-f1e2-4cea-9e08-f525e8242ccf';
        // Static `x-v-request-meta` on reserve (sibling to sign-in's x-sec-navigation-state /
        // upload's x-sec-runtime-state). Value verified from a live browser reserve — yes, it is
        // literally the string "windos.s" (the site's own typo); it is NOT a UUID like the others.
        const reqMeta = this.config.ep_reserve_request_meta || 'windos.s';
        const extraHeaders = { 'x-v-request-meta': reqMeta };
        return await this.callApi(`v1/slots/${slotId}/reserve-slot`, 'POST', body, this.config.ep_reserve_url, parseInt(this.config.ep_reserve_ip_count) || 1, abortController, 0, extraHeaders);
    }

    async getBookingConfig(abortController = null) {
        return (await this._tryRecipe('getBookingConfig', {}, 1, abortController))
            || await this.callApi('v1/appointment/get-booking-config', 'GET', null, this.config.ep_signin_url, 1, abortController);
    }

    // ─── Invoices (post-payment) ─────────────────────────────────────────────────
    // All invoices belonging to the signed-in account. Each entry carries the txrId
    // that the download endpoint below takes as its key.
    async getInvoices(abortController = null) {
        return (await this._tryRecipe('invoices', {}, 1, abortController))
            || await this.callApi('v1/invoice/all-by-user', 'GET', null, this.config.ep_signin_url, 1, abortController);
    }

    // One invoice PDF by transaction id. The PDF is binary — read it from the
    // result's `.body` Buffer; `.data` is the same bytes mangled through utf8.
    // The site guards this route with a Cloudflare Turnstile token sent raw in the
    // x-token header (same as payment-init / upload) — without it the API 500s.
    async downloadInvoice(txrId, turnstileToken = null, abortController = null) {
        const extraHeaders = turnstileToken ? { 'x-token': turnstileToken } : null;
        // Recipe gives the (auto-adjusting) base + path + x-token header; the txrId query is appended.
        const built = this._buildRecipeRequest('invoiceDownload', { turnstileToken });
        const base = built ? built.customBaseUrl : this.config.ep_signin_url;
        const path = built ? built.endpoint : 'v1/invoice/download';
        const hdrs = built ? built.extraHeaders : extraHeaders;
        return await this.callApi(`${path}?txrId=${encodeURIComponent(txrId)}`, 'GET', null, base, 1, abortController, 0, hdrs);
    }

    // Create the booking appointment. The site fires this (empty-body POST) automatically when
    // you ENTER the appointment flow, before any file upload; without it, `v1/file/upload-file`
    // returns 404 "Appointment not found". Response is `{ data:null, statusCode:200, ... }` on
    // success (idempotent — a re-entry just returns success again).
    async createAppointment(abortController = null) {
        return (await this._tryRecipe('createAppointment', {}, parseInt(this.config.ep_fileupload_ip_count) || 1, abortController))
            || await this.callApi('v1/appointment', 'POST', {}, this.config.ep_fileupload_url, parseInt(this.config.ep_fileupload_ip_count) || 1, abortController);
    }

    async initiatePayment(appointmentId, captchaToken = null, abortController = null) {
        // Full recipe replay first — the payment URL (incl. serviceId) and x-token header auto-adjust.
        const builtPay = this._buildRecipeRequest('payment', { ...(appointmentId ? { appointmentId } : {}), turnstileToken: captchaToken });
        if (builtPay) {
            return await this.callApi(builtPay.endpoint, builtPay.method, builtPay.body, builtPay.customBaseUrl, parseInt(this.config.ep_payment_ip_count) || 1, abortController, 0, builtPay.extraHeaders);
        }
        const body = appointmentId ? { appointmentId } : {};
        // Captcha token pulled from the pool is sent raw in the x-token header (no encryption).
        const extraHeaders = captchaToken ? { 'x-token': captchaToken } : null;
        // Path carries a static payment-service UUID: `v1/payment/<serviceId>/dg-epay/initiate`.
        // Verified from a live browser payment-init. The bare `v1/payment/dg-epay/initiate` is an
        // unknown route → 403 "Endpoint not allowed". Unlike the reserve slotId (a plaintext literal),
        // this UUID is stored ENCODED in the bundle, so it can't be regex-scraped like slotId is —
        // update ep_payment_service_id by hand from a live request if the site rotates it.
        const serviceId = this.config.ep_payment_service_id || 'dcd59a95-d55e-41ed-b57c-60416e01617e';
        return await this.callApi(`v1/payment/${serviceId}/dg-epay/initiate`, 'POST', body, this.config.ep_payment_url, parseInt(this.config.ep_payment_ip_count) || 1, abortController, 0, extraHeaders);
    }

    // ─── File-upload step (runs after OTP verify, before Reserve) ───────────────
    // Returns the applicant/file overview: numberOfApplicants + per-applicant files
    // (each with isPrimary and a web file number).
    async getFileOverview(abortController = null) {
        // Method changed: the site now issues POST (not GET) for /file/overview.
        // Path is now PLURAL `over-views` (bundle mrx52llu-V6dyI3yh.js, 2026-07-23; was `over-view`).
        const r = await this._tryRecipe('overviews', {}, parseInt(this.config.ep_fileupload_ip_count) || 1, abortController);
        if (r) return r;
        const overviewsPath = this.config.ep_overviews_path || 'v1/file/over-views';
        return await this.callApi(overviewsPath, 'POST', {}, this.config.ep_fileupload_url, parseInt(this.config.ep_fileupload_ip_count) || 1, abortController);
    }

    // Upload one PDF as multipart/form-data. `turnstileToken` is sent raw in the x-token header
    // (Cloudflare Turnstile), mirroring how payment-init sends its captcha token.
    async uploadFile({ buffer, filename, isPrimary = false, webFileNumber = null, turnstileToken = null }, abortController = null) {
        const formData = { isPrimary: String(!!isPrimary) };
        if (webFileNumber) formData.webFileNumber = webFileNumber;
        // Field name is `files` (PLURAL) — verified against a live browser upload. Sending `file`
        // makes the handler miss the upload entirely and 500 with a generic "INCIDENT-ID …".
        const files = {
            files: { filename: filename || 'document.pdf', content: buffer, contentType: 'application/pdf' }
        };
        // Endpoint uses an UNDERSCORE and is now version-suffixed: `upload_file_v23` (bundle
        // mrx52llu-V6dyI3yh.js, 2026-07-23; was `upload_file`). The hyphen form is an unknown
        // route and the API answers unknown routes with 403 "Endpoint not allowed".
        // The live site also sends `x-sec-runtime-state` (a static token baked into the bundle,
        // sibling to sign-in's x-sec-navigation-state) alongside the raw Turnstile `x-token`.
        const extraHeaders = {};
        if (turnstileToken) extraHeaders['x-token'] = turnstileToken;
        // Captured from a live browser upload (static per bundle; format "v1." + dotted UUID).
        // Without it the API 500s ("INCIDENT-ID …"), exactly like sign-in does without its nav-state.
        const runtimeState = this.config.ep_upload_runtime_state || 'v1.5a4c8831.9a53.47ed.b579.042a2c0cee5a';
        if (runtimeState) extraHeaders['x-sec-runtime-state'] = runtimeState;
        // Full recipe replay first — url + upload headers (x-token, x-sec-runtime-state) auto-adjust;
        // the multipart body is still built here (multipart field bytes aren't captured by the probe).
        const builtUpload = this._buildRecipeRequest('upload', { turnstileToken });
        if (builtUpload) {
            return await this.callApi(
                builtUpload.endpoint, builtUpload.method, null, builtUpload.customBaseUrl,
                parseInt(this.config.ep_fileupload_ip_count) || 1, abortController, 0,
                builtUpload.extraHeaders || (Object.keys(extraHeaders).length ? extraHeaders : null),
                { formData, files }
            );
        }
        const uploadPath = this.config.ep_upload_path || 'v1/file/upload_file_v23';
        return await this.callApi(
            uploadPath, 'POST', null, this.config.ep_fileupload_url,
            parseInt(this.config.ep_fileupload_ip_count) || 1, abortController, 0,
            Object.keys(extraHeaders).length ? extraHeaders : null,
            { formData, files }
        );
    }

    // Confirms uploaded files and reports slot status — the gate that unlocks Reserve.
    async getFileConfirmationAndSlotStatus(abortController = null) {
        // Underscores now on BOTH sides of "and": `file-confirmation_and_slot-status` (bundle
        // mrx52llu-V6dyI3yh.js, 2026-07-23; was `file-confirmation_and-slot-status`). Any other
        // spelling is an unknown route → 403 "Endpoint not allowed".
        return (await this._tryRecipe('fileConfirmation', {}, parseInt(this.config.ep_fileupload_ip_count) || 1, abortController))
            || await this.callApi('v1/file/file-confirmation_and_slot-status', 'GET', null, this.config.ep_fileupload_url, parseInt(this.config.ep_fileupload_ip_count) || 1, abortController);
    }

    // ─── Mission / IVAC center confirmation (runs after upload, before Reserve) ──
    // List of high commissions (missions): [{ id, missionName }]
    async getHighCommissions(abortController = null) {
        return (await this._tryRecipe('highCommissions', {}, parseInt(this.config.ep_fileupload_ip_count) || 1, abortController))
            || await this.callApi('v1/high-commissions', 'GET', null, this.config.ep_fileupload_url, parseInt(this.config.ep_fileupload_ip_count) || 1, abortController);
    }

    // List of IVAC centers for a mission: [{ id, centerName }]. Path carries {missionId} in the recipe.
    async getIvacCenters(missionId, abortController = null) {
        return (await this._tryRecipe('ivacCenters', { missionId }, parseInt(this.config.ep_fileupload_ip_count) || 1, abortController))
            || await this.callApi(`v1/ivac-centers/${encodeURIComponent(missionId)}`, 'GET', null, this.config.ep_fileupload_url, parseInt(this.config.ep_fileupload_ip_count) || 1, abortController);
    }

    // Submit the mission + IVAC center confirmation. The site sends the NAMES, not ids.
    async submitFileConfirmation(mission, ivacCenter, abortController = null) {
        const built = this._buildRecipeRequest('bookingConfig', { mission, ivacCenter });
        if (built) {
            return await this.callApi(built.endpoint, built.method, built.body, built.customBaseUrl, parseInt(this.config.ep_fileupload_ip_count) || 1, abortController, 0, built.extraHeaders);
        }
        const body = { mission, ivacCenter };
        return await this.callApi('v1/appointment/appointment-booking-config', 'POST', body, this.config.ep_fileupload_url, parseInt(this.config.ep_fileupload_ip_count) || 1, abortController);
    }

    // ─── Signup step (auto sign-up) ─────────────────────────────────────────────
    // The live site's registration wizard (verified in the site bundle) is:
    //   1) POST v1/otp/signupOtp {phone, otpChannel:"PHONE"}  x-token=<turnstile>  → { requestId }
    //   2) POST v1/otp/verifyOtp {requestId, phone, code, otpChannel:"PHONE"}
    //   3) POST v1/otp/signupOtp {email, otpChannel:"EMAIL"}  x-token=<turnstile>  → { requestId }
    //   4) POST v1/otp/verifyOtp {requestId, email, code, otpChannel:"EMAIL"}
    //   5) POST v1/auth/signup   {full profile + password + consent + verified tokens/OTPs}
    // The Turnstile token rides raw in the x-token header, exactly like the file-upload step.

    // Request a signup OTP. channel is "PHONE" or "EMAIL"; identifier is the phone / email.
    async sendSignupOtp(channel, identifier, turnstileToken, abortController = null) {
        const body = channel === 'EMAIL'
            ? { email: identifier, otpChannel: 'EMAIL' }
            : { phone: identifier, otpChannel: 'PHONE' };
        const extraHeaders = turnstileToken ? { 'x-token': turnstileToken } : null;
        return await this.callApi('v1/otp/signupOtp', 'POST', body, this.config.ep_signup_url, parseInt(this.config.ep_signup_ip_count) || 1, abortController, 0, extraHeaders);
    }

    // Verify a signup OTP. requestId comes from the matching sendSignupOtp response.
    async verifySignupOtp(channel, identifier, code, requestId, abortController = null) {
        const body = channel === 'EMAIL'
            ? { requestId, email: identifier, code, otpChannel: 'EMAIL' }
            : { requestId, phone: identifier, code, otpChannel: 'PHONE' };
        return await this.callApi('v1/otp/verifyOtp', 'POST', body, this.config.ep_signup_url, parseInt(this.config.ep_signup_ip_count) || 1, abortController);
    }

    // Final account creation. `profile` is the full signup payload the site posts to /auth/signup
    // (built by the signup worker from the queued row + the verified OTPs/turnstile tokens).
    async submitSignup(profile, abortController = null) {
        return await this.callApi('v1/auth/signup', 'POST', profile, this.config.ep_signup_url, parseInt(this.config.ep_signup_ip_count) || 1, abortController);
    }
}

module.exports = {
    IvacApi,
    formatProxyUrl,
    friendlyProtocol
};
