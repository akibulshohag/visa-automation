/**
 * recipeLearner.js — learns the current week's request "recipe" by watching the site's
 * OWN JavaScript make the real requests, then writes it to the config table.
 *
 * Why: every week IVAC rotates endpoint URLs, the reserve slotId / payment serviceId, AND
 * the header NAMES + body field NAMES themselves — only the step SEQUENCE is fixed. Instead
 * of re-reverse-engineering by hand, we load the live site in a real browser, drive the
 * test account through sign-in → OTP → upload → reserve → payment, and intercept each real
 * outgoing API request. For every header/body field we decide whether it is:
 *   • a ROLE placeholder — its value equals a runtime input we control (phone, password,
 *     otp, appointmentDate, the captcha token) or it is the field that CHANGES between two
 *     captures of the same step (→ the captcha), so the transport fills it per-request; or
 *   • a CONSTANT — a static per-bundle value (the current nav-state / request-meta /
 *     runtime-state, whatever they are now named) that we replay verbatim.
 *
 * The result is a recipe api.js can rebuild any request from, immune to key renames. See
 * the schema consumed by IvacApi._buildRecipeRequest() in api.js.
 */

const EventEmitter = require('events');
const { launchRecipeBrowser, WEBSITE_URL } = require('./recipeBrowser');
const { getConfig, setConfig, logger } = require('./database');
const { formatProxyUrl } = require('./api');
const { verifyCipherWithBrowser } = require('./cipherKeys');
const { SiteDriver, withRetry, sleep } = require('./recipeDriver');

// Which real API requests map to which step, matched on stable URL fragments (robust to
// path re-spellings). First matcher that hits wins.
const STEP_MATCHERS = [
    { step: 'signin', test: (u, m) => m === 'POST' && /\/auth\/[^/]*sign-?in/i.test(u) },
    { step: 'verifyOtp', test: (u, m) => m === 'POST' && /otp/i.test(u) && /verif/i.test(u) },
    { step: 'upload', test: (u, m) => m === 'POST' && /\/file\/upload/i.test(u) },
    { step: 'bookingConfig', test: (u, m) => m === 'POST' && /appointment-booking-config/i.test(u) },
    { step: 'reserve', test: (u, m) => m === 'POST' && /reserve-?slot/i.test(u) },
    { step: 'payment', test: (u, m) => m === 'POST' && /(dg-?epay|payment)\b.*initiate/i.test(u) },
];
const ALL_STEPS = STEP_MATCHERS.map((s) => s.step);

// Headers the browser / httpcloak preset manages itself — never replay these from a recipe
// (a stale cookie/boundary/content-length would break the request). Everything else that the
// app code explicitly set (the x-sec-* / x-token / x-v-* family) is what we DO want.
const SKIP_HEADERS = new Set([
    'host', 'connection', 'content-length', 'accept', 'accept-encoding', 'accept-language',
    'user-agent', 'origin', 'referer', 'content-type', 'cookie', 'pragma', 'cache-control',
    'priority', 'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-ch-ua',
    'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'dnt', 'te', 'expires',
    'authorization', // api.js sets this from the bearer token itself
]);

function matchStep(url, method) {
    for (const m of STEP_MATCHERS) { if (m.test(url, method)) return m.step; }
    return null;
}

// Split an absolute API URL into { baseUrl, path } so it slots into callApi(endpoint,
// method, data, customBaseUrl). Prefer the stable "/iams/api/" join the app uses; otherwise
// fall back to origin + pathname so a changed base path is still captured verbatim.
function splitUrl(absUrl) {
    try {
        const u = new URL(absUrl);
        const marker = '/iams/api/';
        const idx = u.pathname.indexOf(marker);
        if (idx !== -1) {
            const cut = idx + marker.length;
            return { baseUrl: u.origin + u.pathname.slice(0, cut), path: u.pathname.slice(cut) + u.search };
        }
        return { baseUrl: u.origin + '/', path: u.pathname.replace(/^\//, '') + u.search };
    } catch (e) {
        return { baseUrl: null, path: absUrl };
    }
}

// A Turnstile token is raw (not cipher-encrypted) when it carries the tell-tale "0." prefix
// and characters (dots, colons) outside the cipher's URL-safe base alphabet. Used to auto-set
// ep_*_encode: if the captcha field is stored raw, encoding is OFF for that flow.
function looksRawTurnstile(v) {
    return typeof v === 'string' && /^0\./.test(v) && /[.:_-]/.test(v) && v.length > 20;
}
function looksHighEntropy(v) {
    return typeof v === 'string' && v.length >= 24 && /[A-Za-z]/.test(v) && /\d/.test(v);
}

// Parse a captured request body into a flat list of { key, value } string entries plus a
// type tag. Handles JSON and multipart/form-data (field names only — file bytes are ignored).
function parseBody(postData, contentType) {
    if (!postData) return { type: 'none', entries: [] };
    const ct = (contentType || '').toLowerCase();
    if (ct.includes('application/json') || /^\s*[\{\[]/.test(postData)) {
        try {
            const obj = JSON.parse(postData);
            if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
                return { type: 'json', entries: Object.keys(obj).map((k) => ({ key: k, value: obj[k] })) };
            }
        } catch (e) { /* not JSON after all */ }
    }
    if (ct.includes('multipart/form-data')) {
        // Match the boundary against the ORIGINAL header — boundaries are case-sensitive, so
        // the lowercased `ct` would corrupt a mixed-case boundary and break the split.
        const m = String(contentType || '').match(/boundary=([^;]+)/i);
        const entries = [];
        if (m) {
            const parts = postData.split('--' + m[1].trim());
            for (const p of parts) {
                const nm = p.match(/name="([^"]+)"/i);
                if (!nm) continue;
                const isFile = /filename="/i.test(p);
                // value = text after the blank line (best-effort; irrelevant for files)
                const vm = p.split(/\r?\n\r?\n/);
                const val = isFile ? '' : (vm[1] || '').replace(/\r?\n$/, '');
                entries.push({ key: nm[1], value: val, isFile });
            }
        }
        return { type: 'multipart', entries };
    }
    return { type: 'raw', entries: [] };
}

// Decide the role (or constant) for one field, given what we fed the walk and which keys were
// observed to CHANGE across repeated captures of this step (the dynamic set → the captcha).
function classify({ key, value, isFile }, location, known, dynamicKeys) {
    const v = value == null ? '' : String(value);
    if (isFile) return { key, role: 'file' };

    // Header device-id can be renamed; recognize by name and let api.js fill it.
    if (location === 'header' && /device/i.test(key)) return { name: key, role: 'deviceId' };

    // Exact value matches against our known runtime inputs.
    if (known.phone && v === known.phone) return loc(location, key, 'phone');
    if (known.password && v === known.password) return loc(location, key, 'password');
    if (known.otpCode && v === known.otpCode) return loc(location, key, 'otpCode');
    if (known.appointmentDate && v === known.appointmentDate) return loc(location, key, 'appointmentDate');
    if (known.appointmentId && v === known.appointmentId) return loc(location, key, 'appointmentId');
    if (known.requestId && v === known.requestId) return loc(location, key, 'requestId');
    if (known.bearer && v === known.bearer) return loc(location, key, 'bearer');

    // The captcha token: raw in a header (x-token) → tokenHeader; in a body field → captcha
    // (api.js encrypts it there when the flow's encode flag is on). Identify it as either a
    // known raw token, a field that CHANGED across captures, a raw Turnstile string, or a
    // long high-entropy blob. Exclude UUIDs (e.g. payment appointmentId is a 36-char UUID
    // that is high-entropy but must NOT be mistaken for the captcha) and require token-length.
    const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
    const isTokenish = (known.tokenRaw && v === known.tokenRaw) ||
        dynamicKeys.has(key) || looksRawTurnstile(v) ||
        (looksHighEntropy(v) && !isUuid && v.length >= 60);
    if (isTokenish) {
        return location === 'header' ? { name: key, role: 'tokenHeader' } : { key, role: 'captcha' };
    }

    // Otherwise it's a static per-bundle constant — replay verbatim.
    return location === 'header' ? { name: key, constant: v } : { key, constant: v };
}
function loc(location, key, role) {
    return location === 'header' ? { name: key, role } : { key, role };
}

// Build one step's recipe from all captures of that step.
function buildStepRecipe(captures, known) {
    const canonical = captures[captures.length - 1];
    const { baseUrl, path } = splitUrl(canonical.url);

    // Diff across captures to find the fields whose values change (→ dynamic, e.g. captcha).
    const dynHeaderKeys = diffKeys(captures.map((c) => c.headerMap));
    const dynBodyKeys = diffKeys(captures.map((c) => bodyMap(c.body)));

    // Headers (curated).
    const headers = [];
    for (const [name, value] of Object.entries(canonical.headerMap)) {
        if (SKIP_HEADERS.has(name.toLowerCase())) continue;
        headers.push(classify({ key: name, value }, 'header', known, dynHeaderKeys));
    }

    // Body.
    let body = { type: canonical.body.type, entries: [] };
    for (const e of canonical.body.entries) {
        body.entries.push(classify(e, 'body', known, dynBodyKeys));
    }

    return { method: canonical.method, baseUrl, path, headers, body };
}

function bodyMap(body) {
    const m = {};
    for (const e of (body.entries || [])) m[e.key] = e.value == null ? '' : String(e.value);
    return m;
}
function diffKeys(maps) {
    const keys = new Set();
    if (maps.length < 2) return keys;
    const allKeys = new Set();
    for (const m of maps) for (const k of Object.keys(m)) allKeys.add(k);
    for (const k of allKeys) {
        const first = maps[0][k];
        if (maps.some((m) => m[k] !== first)) keys.add(k);
    }
    return keys;
}

// Pull the ep_* scalar keys (for backward-compat + easy manual inspection) out of the recipe.
function deriveEpKeys(recipe) {
    const out = {};
    const constHeader = (step, re) => {
        const s = recipe.steps[step];
        if (!s) return null;
        const h = (s.headers || []).find((x) => 'constant' in x && (!re || re.test(x.name)));
        return h ? h.constant : null;
    };
    const navState = constHeader('signin');
    if (navState) out.ep_signin_nav_state = navState;
    const reqMeta = constHeader('reserve');
    if (reqMeta) out.ep_reserve_request_meta = reqMeta;
    const runtimeState = constHeader('upload');
    if (runtimeState) out.ep_upload_runtime_state = runtimeState;

    if (recipe.steps.reserve) {
        const m = String(recipe.steps.reserve.path || '').match(/\/slots\/([^/]+)\/reserve/i);
        if (m) out.ep_reserve_slot_id = m[1];
    }
    if (recipe.steps.payment) {
        const m = String(recipe.steps.payment.path || '').match(/\/payment\/([^/]+)\//i);
        if (m) out.ep_payment_service_id = m[1];
    }
    // Auto-detect whether the captcha body field is stored raw → encode OFF for that flow.
    for (const [flow, step] of [['signin', 'signin'], ['reserve', 'reserve']]) {
        const s = recipe.steps[step];
        if (!s) continue;
        const capEntry = (s.body.entries || []).find((e) => e.role === 'captcha');
        if (capEntry) out[`ep_${flow}_encode`] = capEntry.rawObserved ? '0' : '1';
    }
    return out;
}

// Turn a solver_proxy config string into the { host, port, username, password } object
// puppeteer-real-browser expects, or null for a proxyless launch.
function proxyObjFromConfig(config) {
    const raw = (config.solver_proxy || '').trim();
    if (!raw) return null;
    const formatted = formatProxyUrl(raw);
    if (!formatted) return null;
    try {
        const u = new URL(formatted);
        return {
            host: u.hostname, port: Number(u.port),
            username: u.username ? decodeURIComponent(u.username) : undefined,
            password: u.password ? decodeURIComponent(u.password) : undefined,
        };
    } catch (e) { return null; }
}

// The SPA's root does NOT render the login form — it lives on /signin. That path can rotate
// like everything else, so: try the configured/default one, and if no password field shows up,
// click a "Sign in" link, then fall back to the other common paths. Returns true once a
// password field is actually on screen.
const LOGIN_PATHS = ['/signin', '/login', '/sign-in', '/auth/signin', '/auth/login'];

// After OTP verify the flow moves to its own pages — the SPA doesn't always land there by
// itself, so we navigate explicitly before driving those steps. Overridable per run / via config.
const DEFAULT_STEP_PATHS = { upload: '/file-upload', reserve: '/time-slot' };

// Navigate to `url` unless we're already on it. Returns the URL we ended up on.
async function ensureOnPage(rb, url, log) {
    try {
        const current = rb.page.url();
        const target = new URL(url);
        if (current && new URL(current).pathname === target.pathname) return current;
        log('info', `Navigating to ${url} …`);
        await rb.goto(url);
        await sleep(3000);
    } catch (e) {
        log('warn', `Could not navigate to ${url}: ${e.message}`);
    }
    return rb.page.url();
}

async function ensureLoginForm(rb, driver, startUrl, log) {
    const settle = async () => { await sleep(3500); return await driver.hasField('password'); };

    log('info', `Opening ${startUrl} …`);
    await rb.goto(startUrl);
    if (await settle()) return true;

    // Maybe we landed on the marketing root — follow its own sign-in link.
    log('warn', 'No login form here — looking for a sign-in link…');
    if (await driver.clickButton(/sign ?in|log ?in|login/i)) {
        if (await settle()) { log('info', 'Reached the login form via the site\'s own link.'); return true; }
    }

    // Last resort: walk the usual login paths.
    for (const p of LOGIN_PATHS) {
        const url = WEBSITE_URL.replace(/\/+$/, '') + p;
        if (url === startUrl) continue;
        log('warn', `Trying ${url} …`);
        try { await rb.goto(url); } catch (e) { continue; }
        if (await settle()) { log('info', `Login form found at ${p}.`); return true; }
    }
    log('warn', 'Could not locate a login form automatically — navigate to it in the window; capture continues.');
    return false;
}

// ─── Manual OTP bridge ───────────────────────────────────────────────────────
// The test account's OTP does NOT arrive through the otps.top relay, so the walk pauses and
// waits for the operator to paste the code into the dashboard. submitLearnOtp() (called by
// POST /api/recipe/otp) hands it to the waiting driver, which types it into the site.
let _activeRun = null; // { pendingOtp, otpValue, stopped }

function submitLearnOtp(otp) {
    const code = String(otp || '').trim();
    if (!code) return { ok: false, error: 'empty OTP' };
    if (!_activeRun) return { ok: false, error: 'no learn run in progress' };
    _activeRun.otpValue = code;
    if (_activeRun.pendingOtp) { const r = _activeRun.pendingOtp; _activeRun.pendingOtp = null; r(code); }
    return { ok: true };
}

// Manual override for the captcha gate — "I've solved it, go".
function continueLearn() {
    if (!_activeRun) return { ok: false, error: 'no learn run in progress' };
    _activeRun.continued = true;
    if (_activeRun.pendingContinue) { const r = _activeRun.pendingContinue; _activeRun.pendingContinue = null; r(true); }
    return { ok: true };
}

// The captcha is solved BY THE OPERATOR in the browser window (we never touch it). Block here
// until the widget's response token appears — or until they press Continue. If the page has no
// captcha at all, proceed immediately.
async function waitForCaptcha(driver, state, log, timeoutMs = 300000) {
    if (state.continued) { state.continued = false; return true; }
    if (!await driver.captchaPresent()) return true;
    if (await driver.captchaSolved()) return true;

    log('warn', '🔐 Solve the captcha in the browser window — I continue automatically once it\'s done (or press Continue).');
    const start = Date.now();
    while (Date.now() - start < timeoutMs && !state.stopped) {
        if (state.continued) { state.continued = false; log('info', '▶️ Continue pressed.'); return true; }
        if (await driver.captchaSolved()) { log('info', '🔐 Captcha token detected — continuing.'); return true; }
        await sleep(1500);
    }
    log('warn', '🔐 Gave up waiting on the captcha — submitting anyway.');
    return false;
}

function stopLearn() {
    if (!_activeRun) return { ok: false, error: 'no learn run in progress' };
    _activeRun.stopped = true;
    if (_activeRun.pendingOtp) { const r = _activeRun.pendingOtp; _activeRun.pendingOtp = null; r(null); }
    return { ok: true };
}

function isLearnRunning() { return !!_activeRun; }

// Wait for the operator to submit the OTP from the dashboard.
function waitForManualOtp(state, log, timeoutMs = 300000) {
    if (state.otpValue) { const v = state.otpValue; state.otpValue = null; return Promise.resolve(v); }
    log('info', '📱 Waiting for OTP — paste the code into the dashboard OTP box and press Submit.');
    return new Promise((resolve, reject) => {
        const done = (v) => { clearTimeout(timer); state.pendingOtp = null; v ? resolve(v) : reject(new Error('OTP wait cancelled')); };
        const timer = setTimeout(() => {
            if (state.pendingOtp === done) { state.pendingOtp = null; reject(new Error('OTP not provided in time')); }
        }, timeoutMs);
        state.pendingOtp = done;
    });
}

/**
 * Learn the recipe by AUTO-DRIVING the live site with the test account and intercepting every
 * real request. The driver fills the login, waits for the OTP you paste into the dashboard,
 * attaches the account's own PDF(s), and clicks through reserve/payment — retrying each step
 * on the site's frequent errors. Success is judged by the intercepted RESPONSE status (a real
 * 2xx), not by guessing from the DOM. Any step the driver can't manage degrades to "do it in
 * the window" and capture simply continues, so a partial walk still produces a usable recipe.
 *
 * @param {object} opts
 * @param {string} opts.phone      test-account phone
 * @param {string} opts.password   test-account password
 * @param {string[]} [opts.filePaths] absolute paths to the account's PDF(s) for the upload step
 * @param {string} [opts.appointmentDate] date to pick during reserve
 * @param {number} [opts.timeoutMs=900000] overall budget
 * @param {number} [opts.attempts=5] retries per step
 * @param {function} [opts.onLog] progress callback (level, msg)
 * @param {string[]} [opts.requiredSteps] steps to wait for in the manual grace period
 * @returns {Promise<{ok, recipe, epKeys, cipher, captured}>}
 */
async function learnRecipe(opts = {}) {
    const log = (lvl, msg) => { try { (opts.onLog || (() => {}))(lvl, msg); } catch (e) {} logger[lvl === 'error' ? 'error' : lvl === 'warn' ? 'warn' : 'info'](`[Recipe] ${msg}`); };
    const config = await getConfig();
    const known = {
        phone: opts.phone || null,
        password: opts.password || null,
        appointmentDate: opts.appointmentDate || null,
        otpCode: opts.otpCode || null,
        tokenRaw: null, appointmentId: null, requestId: null, bearer: null,
    };
    const requiredSteps = opts.requiredSteps || ['signin', 'upload', 'reserve', 'payment'];
    const timeoutMs = opts.timeoutMs || 900000;
    const attempts = opts.attempts || 5;
    const filePaths = (opts.filePaths || []).filter(Boolean);

    const captures = {}; // step -> [ {url, method, headerMap, body} ]
    for (const s of ALL_STEPS) captures[s] = [];
    const outcomes = new EventEmitter();   // emits `${step}` with the response status

    const state = { pendingOtp: null, otpValue: null, stopped: false, continued: false, pendingContinue: null };
    _activeRun = state;
    const isStopped = () => state.stopped;

    // Site origin every step path hangs off (derived from the login URL so a domain change
    // only has to be entered once).
    const startUrl = opts.startUrl || config.recipe_start_url || (WEBSITE_URL.replace(/\/+$/, '') + '/signin');
    let base = WEBSITE_URL.replace(/\/+$/, '');
    try { base = new URL(startUrl).origin; } catch (e) { /* keep the default */ }

    // NOTE: no turnstile option — the library's auto-solver is hard-disabled in recipeBrowser.
    // You solve the captcha in the window; waitForCaptcha() blocks until the token appears.
    const rb = await launchRecipeBrowser({
        proxy: proxyObjFromConfig(config),
        log: (m) => log('info', m),
    });
    try {
        // Passively observe every request the site fires; capture the ones we care about.
        rb.page.on('request', (req) => {
            try {
                const url = req.url();
                const method = req.method();
                const step = matchStep(url, method);
                if (!step) return;
                const headerMap = req.headers() || {};
                const body = parseBody(req.postData(), headerMap['content-type']);
                // Learn the bearer opportunistically from what we see.
                if (headerMap['authorization'] && !known.bearer) {
                    known.bearer = headerMap['authorization'].replace(/^Bearer\s+/i, '');
                }
                captures[step].push({ url, method, headerMap, body });
                log('info', `📥 captured ${step} #${captures[step].length} (${method} ${splitUrl(url).path.split('?')[0]})`);
            } catch (e) { /* never let a capture handler throw */ }
        });

        // Success oracle: the REAL response status for a step. Far more reliable than reading
        // the DOM, and it's the same interception we already need for capture.
        rb.page.on('response', (res) => {
            try {
                const req = res.request();
                const step = matchStep(req.url(), req.method());
                if (!step) return;
                const status = res.status();
                log(status >= 200 && status < 300 ? 'info' : 'warn', `↩️ ${step} responded HTTP ${status}`);
                outcomes.emit(step, status);
            } catch (e) { /* ignore */ }
        });

        // Resolves true on a 2xx for `step`, false on a non-2xx, false on timeout.
        const waitForStep = (step, ms) => new Promise((resolve) => {
            const onStatus = (status) => { cleanup(); resolve(status >= 200 && status < 300); };
            const timer = setTimeout(() => { cleanup(); resolve(false); }, ms);
            function cleanup() { clearTimeout(timer); outcomes.removeListener(step, onStatus); }
            outcomes.on(step, onStatus);
        });

        const driver = new SiteDriver(rb.page, log);
        const retryOpts = { attempts, log, isStopped };

        // The login form is on /signin, not the SPA root.
        await ensureLoginForm(rb, driver, startUrl, log);

        await rb.installHook();
        const hasCipher = await rb.hasCipher().catch(() => false);
        log(hasCipher ? 'info' : 'warn', hasCipher ? 'Site cipher function located in the bundle.' : 'Cipher function not found yet (will still capture requests).');

        // ── Step 1: Sign in ──────────────────────────────────────────────────
        // Each failed attempt still fires a real request, so the retries you need anyway also
        // give us the repeat captures that let the tagger tell the captcha from the constants.
        await withRetry('Sign In', async () => {
            if (!await driver.fillField('phone', known.phone)) throw new Error('phone field not found');
            if (!await driver.fillField('password', known.password)) throw new Error('password field not found');
            await waitForCaptcha(driver, state, log);   // you solve it; we just wait for the token
            if (!await driver.clickButton(/sign ?in|log ?in|login|continue|submit|next/i)) throw new Error('submit button not found');
            const ok = await waitForStep('signin', 60000);
            if (!ok) { const errs = await driver.pageErrors(); if (errs.length) log('warn', `site says: ${errs.join(' | ')}`); }
            return ok;
        }, retryOpts);

        // ── Step 2: Verify OTP (manual input) ────────────────────────────────
        if (!isStopped()) await withRetry('Verify OTP', async () => {
            const otp = await waitForManualOtp(state, log);
            if (!otp) throw new Error('no OTP provided');
            known.otpCode = String(otp);   // lets the tagger mark the OTP field role:otpCode
            if (!await driver.fillField('otp', otp)) throw new Error('OTP field not found');
            if (!await driver.clickButton(/verify|confirm|submit|continue|next/i)) throw new Error('verify button not found');
            const ok = await waitForStep('verifyOtp', 60000);
            if (!ok) { const errs = await driver.pageErrors(); if (errs.length) log('warn', `site says: ${errs.join(' | ')}`); }
            return ok;
        }, retryOpts);

        // ── Step 3: File upload (the account's OWN PDFs) ─────────────────────
        // Lives on its own page (/file-upload) — go there first.
        if (!isStopped()) {
            if (filePaths.length === 0) {
                log('warn', '📄 No PDF supplied for this run — upload it in the browser window to capture the upload step.');
            } else {
                await ensureOnPage(rb, base + (opts.uploadPath || config.recipe_upload_path || DEFAULT_STEP_PATHS.upload), log);
                await withRetry('File Upload', async () => {
                    if (!await driver.attachFiles(filePaths)) throw new Error('file input not found');
                    await sleep(1200);
                    await driver.clickButton(/upload|submit|continue|next|save/i);
                    const ok = await waitForStep('upload', 90000);
                    if (!ok) { const errs = await driver.pageErrors(); if (errs.length) log('warn', `site says: ${errs.join(' | ')}`); }
                    return ok;
                }, retryOpts);
            }
        }

        // ── Steps 4-5: Reserve + Payment ─────────────────────────────────────
        // These depend on live slot availability and a date picker, so they are best-effort:
        // we click the obvious controls and let the operator finish in the window if needed.
        if (!isStopped()) await ensureOnPage(rb, base + (opts.reservePath || config.recipe_reserve_path || DEFAULT_STEP_PATHS.reserve), log);
        if (!isStopped()) await withRetry('Reserve Slot', async () => {
            await waitForCaptcha(driver, state, log);   // reserve carries its own captcha
            await driver.clickButton(/reserve|book|confirm|proceed|continue|next/i);
            const ok = await waitForStep('reserve', 60000);
            if (!ok) { const errs = await driver.pageErrors(); if (errs.length) log('warn', `site says: ${errs.join(' | ')}`); }
            return ok;
        }, { ...retryOpts, attempts: Math.min(attempts, 3) });

        if (!isStopped()) await withRetry('Payment Init', async () => {
            await driver.clickButton(/pay|payment|proceed|continue|confirm/i);
            const ok = await waitForStep('payment', 60000);
            if (!ok) { const errs = await driver.pageErrors(); if (errs.length) log('warn', `site says: ${errs.join(' | ')}`); }
            return ok;
        }, { ...retryOpts, attempts: Math.min(attempts, 3) });

        // ── Grace period: finish anything the driver couldn't, by hand ───────
        const missing = () => requiredSteps.filter((s) => captures[s].length === 0);
        if (!isStopped() && missing().length) {
            log('warn', `👉 Still missing: ${missing().join(', ')}. Finish those in the browser window — still capturing.`);
            const start = Date.now();
            while (Date.now() - start < timeoutMs && missing().length && !isStopped()) await sleep(2000);
        }
        if (missing().length) log('warn', `Proceeding without: ${missing().join(', ')}. Writing what was captured.`);

        // Verify the local cipher still matches the site (best-effort — needs the bundle loaded).
        let cipher = null;
        try { cipher = await verifyCipherWithBrowser(rb); } catch (e) { log('warn', `Cipher verify skipped: ${e.message}`); }

        // Build the recipe from whatever we captured.
        const recipe = { version: 1, learnedAt: new Date().toISOString(), steps: {} };
        for (const step of ALL_STEPS) {
            if (captures[step].length === 0) continue;
            const s = buildStepRecipe(captures[step], known);
            // Note whether the captcha body field was observed raw (drives ep_*_encode).
            const cap = (s.body.entries || []).find((e) => e.role === 'captcha');
            if (cap) {
                const canonical = captures[step][captures[step].length - 1];
                const rawEntry = (canonical.body.entries || []).find((e) => e.key === cap.key);
                cap.rawObserved = rawEntry ? looksRawTurnstile(String(rawEntry.value)) : false;
            }
            recipe.steps[step] = s;
        }

        const epKeys = deriveEpKeys(recipe);

        // Persist: the consolidated recipe + the derived ep_* scalars + provenance.
        await setConfig('recipe_json', JSON.stringify(recipe));
        await setConfig('recipe_pulled_at', recipe.learnedAt);
        for (const [k, v] of Object.entries(epKeys)) {
            if (v != null) await setConfig(k, String(v));
        }

        const capturedSummary = ALL_STEPS.filter((s) => captures[s].length).map((s) => `${s}×${captures[s].length}`).join(', ');
        log('info', `✅ Recipe written. Steps: ${Object.keys(recipe.steps).join(', ') || 'none'}. Captures: ${capturedSummary || 'none'}.`);
        if (Object.keys(epKeys).length) log('info', `Derived ep_* keys: ${Object.keys(epKeys).join(', ')}`);

        return { ok: Object.keys(recipe.steps).length > 0, recipe, epKeys, cipher, captured: capturedSummary };
    } finally {
        _activeRun = null;
        await rb.close();
    }
}

module.exports = {
    learnRecipe, submitLearnOtp, stopLearn, continueLearn, isLearnRunning,
    _internals: { buildStepRecipe, classify, parseBody, splitUrl, deriveEpKeys, matchStep },
};
