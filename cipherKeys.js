/**
 * cipherKeys.js — Dynamic Cipher Key Auto-Updater
 * 
 * Fetches the IVAC website's JS bundle, extracts cipher configs,
 * evaluates obfuscated secrets, and provides universal encrypt/decrypt.
 * Keys are persisted in the MySQL `config` table and used until re-pulled.
 */

const vm = require('vm');
const fs = require('fs');
const path = require('path');
const httpcloak = require('httpcloak');
const cipherAst = require('./cipherAst');
const { logger, getConfig, setConfig, getAllProxies } = require('./database');

// ─── Local bundle cache (live-first, fall back to local when the site is off / 403) ──────────
// Every successful pull saves the winning bundle here; when the live fetch fails we reuse it, so
// the panel keeps working with the last-known bundle instead of hard-failing.
const LOCAL_BUNDLE_FILE = path.join(__dirname, 'last-bundle.local.js');
const LOCAL_BUNDLE_META = path.join(__dirname, 'last-bundle.local.json');

function saveLocalBundle(text, url) {
    fs.writeFileSync(LOCAL_BUNDLE_FILE, text);
    fs.writeFileSync(LOCAL_BUNDLE_META, JSON.stringify({ url, savedAt: new Date().toISOString(), bytes: text.length }));
}

// Return { text, url } of the best local bundle, or null. Prefers the auto-saved cache from the
// last successful pull; otherwise the largest app-bundle .js shipped in the repo (e.g. the
// mrx52llu-*.js snapshots).
function loadLocalBundle() {
    try {
        if (fs.existsSync(LOCAL_BUNDLE_FILE)) {
            const text = fs.readFileSync(LOCAL_BUNDLE_FILE, 'utf8');
            let url = 'local-cache';
            try { url = JSON.parse(fs.readFileSync(LOCAL_BUNDLE_META, 'utf8')).url || url; } catch (e) { /* no meta */ }
            if (text && text.length > 1000) return { text, url };
        }
    } catch (e) { /* fall through to repo snapshots */ }
    try {
        const files = fs.readdirSync(__dirname)
            .filter((f) => /^[a-z0-9]+-[A-Za-z0-9_]+\.js$/i.test(f)) // hashed app-bundle names
            .map((f) => ({ f, size: fs.statSync(path.join(__dirname, f)).size }))
            .filter((x) => x.size > 500000)
            .sort((a, b) => b.size - a.size);
        if (files.length) return { text: fs.readFileSync(path.join(__dirname, files[0].f), 'utf8'), url: files[0].f };
    } catch (e) { /* none */ }
    return null;
}

// Default alphabet — overridden dynamically from pulled bundle data
let ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_';
let ALPHA_LEN = ALPHABET.length; // 64

function setAlphabet(newAlphabet) {
    if (newAlphabet && newAlphabet.length >= 10) {
        ALPHABET = newAlphabet;
        ALPHA_LEN = newAlphabet.length;
    }
}

const WEBSITE_URL = 'https://appointment.ivacbd.com';

// ─── httpcloak fetch (Cloudflare-safe) ───────────────────────────────────────
// The site sits behind Cloudflare bot management, which fingerprints the TLS/HTTP
// stack. got-scraping uses Node's TLS and gets 403'd as a bot — which is why a real
// browser sees 200 while the old cipher pull kept seeing 403. We fetch through the
// SAME Go-backed httpcloak client (real Chrome JA3/JA4 + HTTP/2|3 fingerprint) that
// the rest of the app migrated to, so the cipher pull gets through like the browser.
//
// One persistent session is reused across attempts so its cookie jar + warm
// connection behave like a browser that already cleared Cloudflare.
//
// Default is HTTP/2, NOT HTTP/3. The pull connects DIRECTLY (no proxy) to the IVAC
// origin, and HTTP/3 = QUIC over UDP/443, which many ISPs throttle or block. On those
// networks the QUIC handshake stalls until timeout on every fresh process, making
// "Pull Latest Keys" hang for ~10s+ while the proxied bot/test paths (TCP) stay fast.
// HTTP/2 carries the SAME real-Chrome JA3/JA4 TLS fingerprint, so Cloudflare lets it
// through identically — only the transport changes. (Set to 'h3' here to opt back in.)
// ─── Pull context (per-worker session state) ─────────────────────────────────
// A "pull context" bundles ONE httpcloak session + its own HTTP-version downgrade
// state + an optional proxy + an optional AbortSignal. The single manual pull uses a
// shared DIRECT context; the multi-worker auto-pull gives EACH worker its own context
// (own proxy, own AbortController) so workers are fully independent and cancellable.

// One-step downgrade ladder for transport failures: QUIC (h3) → HTTP/2 → HTTP/1.1.
// h3→h2 covers networks that block UDP/443; h2→h1 covers a Cloudflare edge that
// negotiates http/1.1 at the TLS ALPN handshake ("ALPN mismatch: expected h2, got
// http/1.1"), which httpcloak rejects outright when h2 is forced.
const _HTTP_DOWNGRADE = { h3: 'h2', h2: 'h1' };

function _buildCipherSession(httpVersion, proxyUrl) {
    const opts = {
        preset: 'chrome-146-windows',
        httpVersion: httpVersion || 'h2',
        // Short timeout on purpose: the pull is a one-shot fetch of the HTML + every
        // /assets bundle, so a wedged request must NOT burn 30s each (on a bad network
        // that stacks up to minutes and looks like a full hang). A healthy h2/h3 request
        // completes in 1-2s; 12s is a safe upper bound.
        timeout: 12,          // seconds
        verify: false,
        quicIdleTimeout: 20,
    };
    // Route this context's traffic through a proxy when the worker was assigned one.
    if (proxyUrl) opts.proxy = proxyUrl;
    return new httpcloak.Session(opts);
}

// Create a fresh pull context. `session` is built lazily on first use so an aborted
// worker that never fires a request doesn't allocate a Go-backed session.
function makePullContext({ proxyUrl = null, httpVersion = 'h2', signal = null, label = '' } = {}) {
    return { proxyUrl, httpVersion, signal, label, session: null };
}

function ctxGetSession(ctx) {
    if (!ctx.session) ctx.session = _buildCipherSession(ctx.httpVersion, ctx.proxyUrl);
    return ctx.session;
}

function ctxResetSession(ctx) {
    if (ctx.session) { try { ctx.session.close(); } catch (e) { /* ignore */ } }
    ctx.session = null;
}

// Fully dispose a context: closes its session (tears down in-flight connections).
function ctxClose(ctx) {
    if (ctx) ctxResetSession(ctx);
}

// Build request options for a context — attach the AbortSignal only when the context
// has one (a stray `signal: null` can confuse the Go FFI binding).
function _reqOpts(ctx, extra) {
    const o = { ...extra };
    if (ctx.signal) o.signal = ctx.signal;
    return o;
}

// Shared DIRECT context for the single manual pull (POST /api/cipher/pull) and any
// pullCipherKeys() call made without an explicit context. Persisted at module scope so
// its warm connection + cookie jar survive across manual pulls.
let _defaultCtx = null;
function getDefaultCtx() {
    if (!_defaultCtx) _defaultCtx = makePullContext({ httpVersion: 'h2', label: '' });
    return _defaultCtx;
}

// Shutdown cleanup: stop the auto-pull worker pool and free every Go-backed httpcloak
// session so QUIC/TLS connections don't keep the event loop ref'd open on Ctrl+C.
// Safe to call when nothing is running.
function closeCipherSession() {
    try { stopAutoPull(); } catch (e) { /* ignore */ }
    if (_defaultCtx) { ctxClose(_defaultCtx); _defaultCtx = null; }
}

/**
 * GET a URL through the context's httpcloak session. Returns { statusCode, body,
 * protocol }. No-cache headers + the caller's cache-busting query string mimic a
 * browser hard reload so we never read a stale, edge-cached 403.
 */
async function cipherHttpGet(url, accept, ctx) {
    const headers = {
        'accept': accept || 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache, no-store, max-age=0',
        'pragma': 'no-cache',
    };
    try {
        const res = await ctxGetSession(ctx).request('GET', url, _reqOpts(ctx, { headers }));
        return { statusCode: res.statusCode, body: res.text, protocol: res.protocol };
    } catch (e) {
        // A cancelled worker aborts mid-request — surface that as-is, never downgrade on it.
        if (ctx.signal && ctx.signal.aborted) throw e;
        // Transport failure (DNS/TLS/QUIC/ALPN/timeout). Rebuild on the next-lower HTTP
        // version and retry once on the fresh session. The downgrade is sticky on THIS
        // context so later attempts stay on the version that actually works.
        ctxResetSession(ctx);
        const next = _HTTP_DOWNGRADE[ctx.httpVersion];
        if (next) {
            logger.warn(`[CipherKeys] ${ctx.httpVersion.toUpperCase()} fetch failed (${e.message}); falling back to ${next.toUpperCase()}.`);
            ctx.httpVersion = next;
            const res = await ctxGetSession(ctx).request('GET', url, _reqOpts(ctx, { headers }));
            return { statusCode: res.statusCode, body: res.text, protocol: res.protocol };
        }
        throw e;
    }
}

// DB config keys for persistence
const DB_KEYS = {
    signin_key: 'cipher_signin_key',
    signin_startAt: 'cipher_signin_startAt',
    signin_length: 'cipher_signin_length',
    signin_version: 'cipher_signin_version',
    reserve_key: 'cipher_reserve_key',
    reserve_startAt: 'cipher_reserve_startAt',
    reserve_length: 'cipher_reserve_length',
    reserve_version: 'cipher_reserve_version',
    bundle_url: 'cipher_bundle_url',
    pulled_at: 'cipher_pulled_at',
    alphabet: 'cipher_alphabet',
    functions_code: 'cipher_functions_code', // [legacy] single native encrypt/decrypt module
    modules_json: 'cipher_modules_json',     // JSON: { versionMap, modulesByVersion } — all algorithms keyed by version
};

// In-memory cache (loaded from DB on init)
let cache = {
    signin: null,   // { key, startAt, length, version }
    reserve: null,  // { key, startAt, length, version }
    bundleUrl: null,
    pulledAt: null,
    alphabet: null, // Dynamic charset from bundle
    // The site ships ONE cipher algorithm per `version` (1..N) and selects it by the
    // config's version field. We evaluate and cache every version's native functions here.
    nativeByVersion: {}, // { "9": { encryptText, decryptText }, "10": {...}, ... }
    versionMap: {},      // { "9": "L1", "10": "a4", ... } — version → bundle export var (for diagnostics)
    loaded: false,
};

// ─── Native Function Extractor ───────────────────────────────────────────────

// Marker that closes every Object.freeze(Object.defineProperty(...)) module export.
// Each crypto module is fully self-contained between two of these markers.
const MODULE_END_MARKER = ',{value:"Module"}))';

/**
 * Extract the EXACT encrypt/decrypt functions from the bundle, keyed by version.
 *
 * The site ships one cipher algorithm per version and selects it at runtime via a
 * dispatcher map (obfuscated name, e.g. `vU`):
 *
 *   const vU={1:()=>Xe(()=>Promise.resolve().then(()=>BX)), ... 9:()=>...(()=>L1), ...}
 *   const o=vU[version]; ... encryptText(token, secret, startAt, length)
 *
 * So `version` (from each cipher config) directly selects which module's
 * encryptText/decryptText to use. We:
 *   1. Parse that dispatcher map -> { version: exportVar }.
 *   2. For every `EXPORTVAR=Object.freeze(Object.defineProperty({...decryptText:D,encryptText:E},...))`
 *      slice the full self-contained module (between the previous module marker and this one).
 *   3. Map version -> wrapped, self-evaluating module code.
 *
 * Each module embeds its own self-test (`if(decrypt(encrypt(...))!==...)throw`), so evaluating
 * the slice also VALIDATES that the extraction is complete.
 *
 * Returns { versionMap, modulesByVersion, exportsByVar } or null if nothing found.
 */
function extractCipherModules(bundleText) {
    // 1. Parse the dispatcher: version -> export var. The map name is obfuscated and
    //    changes every build, so we match on the stable structural shape instead.
    //    e.g.  9:()=>Xe(()=>Promise.resolve().then(()=>L1))
    const versionMap = {};
    const mapEntryRe = /(\d{1,3}):\(\)=>[A-Za-z_$][\w$]*\(\(\)=>Promise\.resolve\(\)\.then\(\(\)=>([A-Za-z_$][\w$]*)\)\)/g;
    let me;
    while ((me = mapEntryRe.exec(bundleText)) !== null) {
        versionMap[me[1]] = me[2];
    }

    // 2. Locate every crypto module export and capture its self-contained source.
    //    e.g. const L1=Object.freeze(Object.defineProperty({__proto__:null,decryptText:q1,encryptText:G1},Symbol.toStringTag,{value:"Module"}))
    const exportRe = /([A-Za-z_$][\w$]*)=Object\.freeze\(Object\.defineProperty\(\{(?:__proto__:null,)?decryptText:([A-Za-z_$][\w$]*),encryptText:([A-Za-z_$][\w$]*)\}/g;
    const exportsByVar = {}; // exportVar -> { encFn, decFn, code }
    let em;
    while ((em = exportRe.exec(bundleText)) !== null) {
        const exportVar = em[1];
        const decFn = em[2];
        const encFn = em[3];

        // End of this module = the closing `,{value:"Module"}))` right after the match.
        const endMarkerPos = bundleText.indexOf(MODULE_END_MARKER, em.index);
        if (endMarkerPos < 0) continue;
        const moduleEnd = endMarkerPos + MODULE_END_MARKER.length;

        // Start of this module = just after the PREVIOUS module's end marker. Each module is
        // independent (own string table + decoders), so this slice is the whole algorithm.
        const prevMarkerPos = bundleText.lastIndexOf(MODULE_END_MARKER, em.index - 1);
        const moduleStart = prevMarkerPos < 0 ? 0 : prevMarkerPos + MODULE_END_MARKER.length;

        const section = bundleText.slice(moduleStart, moduleEnd);
        const code = `(function(){\n${section}\nreturn {encryptText: typeof ${encFn}!=='undefined'?${encFn}:null, decryptText: typeof ${decFn}!=='undefined'?${decFn}:null};\n})()`;
        exportsByVar[exportVar] = { encFn, decFn, code };
    }

    if (Object.keys(exportsByVar).length === 0) return null;

    // 3. Build version -> module code map. If the dispatcher couldn't be parsed, fall back
    //    to indexing the crypto exports in source order (1-based), which matches the site's
    //    own numbering convention.
    const modulesByVersion = {};
    if (Object.keys(versionMap).length > 0) {
        for (const [version, exportVar] of Object.entries(versionMap)) {
            if (exportsByVar[exportVar]) modulesByVersion[version] = exportsByVar[exportVar].code;
        }
    } else {
        let i = 1;
        for (const exportVar of Object.keys(exportsByVar)) {
            modulesByVersion[String(i++)] = exportsByVar[exportVar].code;
        }
    }

    return { versionMap, modulesByVersion, exportsByVar };
}

// ─── Native Module Evaluation ────────────────────────────────────────────────

function evalModuleCode(code) {
    const sandbox = {
        decodeURIComponent, encodeURIComponent, String, Math, parseInt, parseFloat,
        Array, Object, RegExp, Error, Boolean, Number, Symbol, BigInt, JSON, isNaN, isFinite,
    };
    const ctx = vm.createContext(sandbox);
    const result = vm.runInContext(code, ctx, { timeout: 10000 });
    if (result && typeof result.encryptText === 'function' && typeof result.decryptText === 'function') {
        return { encryptText: result.encryptText, decryptText: result.decryptText };
    }
    return null;
}

function loadNativeModules(modulesByVersion) {
    const loaded = {};
    for (const [version, code] of Object.entries(modulesByVersion || {})) {
        try {
            const fns = evalModuleCode(code);
            if (fns) loaded[version] = fns;
            else logger.warn(`[CipherKeys] Native module v${version} did not export usable functions.`);
        } catch (e) {
            // A throw here usually means the module's own self-test failed (incomplete slice).
            logger.error(`[CipherKeys] Failed to eval native module v${version}: ${e.message}`);
        }
    }
    return loaded;
}

function getNativeForVersion(version) {
    const v = String(version);
    if (cache.nativeByVersion && cache.nativeByVersion[v]) return cache.nativeByVersion[v];
    return null;
}

// ─── Universal Encrypt for Bot ───────────────────────────────────────────────

function encryptCaptcha(token, flow) {
    const params = flow === 'reserve' ? cache.reserve : cache.signin;
    if (!params || !params.key) {
        logger.warn(`[CipherKeys] No cached keys for flow "${flow}". Returning raw token.`);
        return token;
    }
    const mod = getNativeForVersion(params.version);
    if (!mod) {
        logger.warn(`[CipherKeys] No native module for flow "${flow}" version ${params.version}. Returning raw token.`);
        return token;
    }
    try {
        // Exact site call signature: encryptText(token, secret, startAt, length)
        return mod.encryptText(token, params.key, params.startAt, params.length);
    } catch (e) {
        logger.error(`[CipherKeys] Native encryption failed (v${params.version}): ${e.message}`);
        return token;
    }
}

// ─── DB Persistence ──────────────────────────────────────────────────────────

async function loadFromDb() {
    try {
        const config = await getConfig();

        // Load alphabet first so encrypt/seed functions use it
        if (config[DB_KEYS.alphabet]) {
            cache.alphabet = config[DB_KEYS.alphabet];
            setAlphabet(cache.alphabet);
            logger.info(`[CipherKeys] Loaded alphabet from DB: "${ALPHABET.slice(0, 20)}..." (${ALPHA_LEN} chars)`);
        }

        // Load per-version native modules (all algorithms, keyed by version)
        if (config[DB_KEYS.modules_json]) {
            try {
                const parsed = JSON.parse(config[DB_KEYS.modules_json]);
                cache.versionMap = parsed.versionMap || {};
                cache.nativeByVersion = loadNativeModules(parsed.modulesByVersion || {});
                const versions = Object.keys(cache.nativeByVersion);
                if (versions.length) {
                    logger.info(`[CipherKeys] Loaded native cipher modules from DB for versions: ${versions.join(', ')}`);
                }
            } catch (e) {
                logger.error(`[CipherKeys] Failed to load native modules from DB: ${e.message}`);
            }
        } else if (config[DB_KEYS.functions_code]) {
            // Legacy single-module fallback (pre version-aware extraction).
            try {
                const fns = evalModuleCode(config[DB_KEYS.functions_code]);
                if (fns) {
                    // Legacy code was always module index 1.
                    cache.nativeByVersion['1'] = fns;
                    logger.info(`[CipherKeys] Loaded legacy native functions from DB (mapped to version 1).`);
                }
            } catch (e) {
                logger.error(`[CipherKeys] Failed to evaluate legacy native functions from DB: ${e.message}`);
            }
        }

        if (config[DB_KEYS.signin_key]) {
            cache.signin = {
                key: config[DB_KEYS.signin_key],
                startAt: parseInt(config[DB_KEYS.signin_startAt]) || 0,
                length: parseInt(config[DB_KEYS.signin_length]) || 0,
                version: parseInt(config[DB_KEYS.signin_version]) || 10,
            };
        }

        if (config[DB_KEYS.reserve_key]) {
            cache.reserve = {
                key: config[DB_KEYS.reserve_key],
                startAt: parseInt(config[DB_KEYS.reserve_startAt]) || 0,
                length: parseInt(config[DB_KEYS.reserve_length]) || 0,
                version: parseInt(config[DB_KEYS.reserve_version]) || 6,
            };
        }

        cache.bundleUrl = config[DB_KEYS.bundle_url] || null;
        cache.pulledAt = config[DB_KEYS.pulled_at] || null;
        cache.loaded = true;

        if (cache.signin) {
            logger.info(`[CipherKeys] Loaded SignIn cipher from DB: v${cache.signin.version}, startAt=${cache.signin.startAt}, length=${cache.signin.length}, key=${cache.signin.key.slice(0, 8)}...`);
        }
        if (cache.reserve) {
            logger.info(`[CipherKeys] Loaded Reserve cipher from DB: v${cache.reserve.version}, startAt=${cache.reserve.startAt}, length=${cache.reserve.length}, key=${cache.reserve.key.slice(0, 8)}...`);
        }
        if (!cache.signin && !cache.reserve) {
            logger.warn(`[CipherKeys] No cached cipher keys in DB. Pull keys from the dashboard.`);
        }
    } catch (err) {
        logger.error(`[CipherKeys] Failed to load from DB: ${err.message}`);
    }
}

async function saveToDb(signin, reserve, bundleUrl, alphabet, modulesData) {
    const now = new Date().toISOString();

    if (alphabet) {
        await setConfig(DB_KEYS.alphabet, alphabet);
        cache.alphabet = alphabet;
        setAlphabet(alphabet);
    }
    if (modulesData && modulesData.modulesByVersion) {
        await setConfig(DB_KEYS.modules_json, JSON.stringify({
            versionMap: modulesData.versionMap || {},
            modulesByVersion: modulesData.modulesByVersion,
        }));
        // Evaluate immediately so the new modules are usable right away.
        cache.versionMap = modulesData.versionMap || {};
        cache.nativeByVersion = loadNativeModules(modulesData.modulesByVersion);
    }
    if (signin) {
        await setConfig(DB_KEYS.signin_key, signin.key);
        await setConfig(DB_KEYS.signin_startAt, String(signin.startAt));
        await setConfig(DB_KEYS.signin_length, String(signin.length));
        await setConfig(DB_KEYS.signin_version, String(signin.version));
        cache.signin = signin;
    }
    if (reserve) {
        await setConfig(DB_KEYS.reserve_key, reserve.key);
        await setConfig(DB_KEYS.reserve_startAt, String(reserve.startAt));
        await setConfig(DB_KEYS.reserve_length, String(reserve.length));
        await setConfig(DB_KEYS.reserve_version, String(reserve.version));
        cache.reserve = reserve;
    }
    if (bundleUrl) {
        await setConfig(DB_KEYS.bundle_url, bundleUrl);
        cache.bundleUrl = bundleUrl;
    }
    await setConfig(DB_KEYS.pulled_at, now);
    cache.pulledAt = now;

    logger.info(`[CipherKeys] Saved to DB at ${now}`);
}

// ─── Bundle Fetching & Parsing ───────────────────────────────────────────────

async function fetchWebsiteHtml(ctx) {
    // Cache-bust like a browser hard reload (unique query string + no-cache headers).
    const url = `${WEBSITE_URL}?_cb=${Date.now()}`;
    const { statusCode, body, protocol } = await cipherHttpGet(url, undefined, ctx);
    logger.info(`[CipherKeys] Website fetch: HTTP ${statusCode} (${protocol || 'h?'})`);
    if (statusCode < 200 || statusCode >= 300) {
        throw new Error(`Failed to fetch IVAC website: HTTP ${statusCode}`);
    }
    return body;
}

// Extract the reserve-slot service id (the "reserve id") straight from the bundle. The
// reserve endpoint is `v1/slots/<slotId>/reserve-slot`, and the site bakes that full path
// in as ONE plaintext string literal (`"/slots/ccd3dd63-…-c65eaa4fc663/reserve-slot"`), so —
// unlike the cipher secret — no decoding is needed: match the UUID between `/slots/` and
// `/reserve-slot`. Returns the id string, or null if the pattern isn't present. If the site
// ever ships more than one, we take the first (there has only ever been one).
function extractReserveSlotId(bundleText) {
    const m = bundleText.match(/\/slots\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\/reserve-slot/);
    return m ? m[1] : null;
}

function extractBundleUrls(html) {
    const urls = [];
    const re = /src\s*=\s*["']([^"']*\/assets\/[^"']+\.js[^"']*)["']/g;
    let m;
    while ((m = re.exec(html)) !== null) {
        let url = m[1];
        if (url.startsWith('/')) url = 'https://appointment.ivacbd.com' + url;
        urls.push(url.split('?')[0]);
    }
    return [...new Set(urls)];
}

// Per-bundle body-read budget. The HTML fetch is tiny and stays on the snappy 12s
// session default, but the main app bundle is several hundred KB-to-MB; under any
// download contention its body read alone can exceed 12s ("read_body ... context
// deadline exceeded"), which is exactly what was failing. 30s is a generous ceiling
// for the one bundle we actually need while still failing fast on a wedged network.
const BUNDLE_TIMEOUT_SEC = 30;

// Cache-FRIENDLY headers, used for the first (fast) bundle attempt. A browser
// requests these subresources WITHOUT no-cache so Cloudflare answers from its edge.
const BUNDLE_HEADERS = {
    'accept': 'application/javascript,text/javascript,*/*;q=0.8',
    'accept-language': 'en-US,en;q=0.9',
};

// Cache-BUSTING headers, used only as a fallback if the clean fetch fails (e.g. the
// rare edge-cached 403 right after a new build).
const BUNDLE_HEADERS_NOCACHE = {
    ...BUNDLE_HEADERS,
    'cache-control': 'no-cache, no-store, max-age=0',
    'pragma': 'no-cache',
};

/**
 * Download every bundle in true parallel — each on its OWN connection, and each
 * straight from Cloudflare's edge cache.
 *
 * TWO things made the old path slow:
 *
 *  1. Shared connection. All bundles multiplexed onto ONE HTTP/2 connection and split
 *     its flow-control + TCP window, so the big main bundle got starved and its body
 *     read spilled past the timeout. fork() hands back sessions that share cookies +
 *     TLS tickets (cheap 0-RTT off the warm HTML connection) but use INDEPENDENT
 *     connections — the browser-tab model — so each bundle downloads on its own pipe.
 *
 *  2. Cache bypass. The bundle name is a Vite CONTENT HASH (e.g. mqz3c7bf-…js): the
 *     file is immutable and Cloudflare caches it at the edge with a long TTL. The old
 *     code appended `?_cb=<now>` AND sent `no-cache`, which forced CF to bypass that
 *     edge cache and re-pull the whole multi-MB bundle from the slow origin on EVERY
 *     pull (~26s observed). A browser just requests the clean URL and gets the
 *     brotli-compressed copy from the edge in ~1-2s. So we now fetch the CLEAN url with
 *     cache-friendly headers first; the hash guarantees freshness. Only if that fails
 *     do we retry with the old cache-busting query + no-cache headers, to cover the
 *     rare edge-cached-403-after-deploy case the buster was originally added for.
 *
 * Forks are disposable: closed in the finally so they don't leak.
 *
 * Returns a Promise.allSettled-shaped array of { status, value:{url,text} | reason }.
 */
async function fetchBundlesParallel(urls, ctx) {
    const session = ctxGetSession(ctx);
    let forks = [];
    try {
        forks = session.fork(urls.length);
    } catch (e) {
        logger.warn(`[CipherKeys] fork() failed (${e.message}); falling back to shared session.`);
        forks = [];
    }
    try {
        return await Promise.allSettled(urls.map(async (url, i) => {
            const s = forks[i] || session;

            // Attempt 1: clean URL, cache-friendly → served from CF edge cache (fast).
            let res = await s.request('GET', url, _reqOpts(ctx, { headers: BUNDLE_HEADERS, timeout: BUNDLE_TIMEOUT_SEC }));

            // Attempt 2 (only on failure): cache-busted + no-cache, hits the origin.
            if (res.statusCode < 200 || res.statusCode >= 300) {
                const sep = url.includes('?') ? '&' : '?';
                const bustedUrl = `${url}${sep}_cb=${Date.now()}`;
                res = await s.request('GET', bustedUrl, _reqOpts(ctx, { headers: BUNDLE_HEADERS_NOCACHE, timeout: BUNDLE_TIMEOUT_SEC }));
            }

            if (res.statusCode < 200 || res.statusCode >= 300) {
                throw new Error(`Failed to fetch bundle: HTTP ${res.statusCode}`);
            }
            return { url, text: res.text };
        }));
    } finally {
        for (const f of forks) {
            try { f.close(); } catch (_) { /* ignore */ }
        }
    }
}

// ─── Alphabet Extraction ─────────────────────────────────────────────────────

function findAlphabet(text) {
    // Search for string literals that look like cipher alphabets:
    // 62-68 chars containing all digits (0-9), lowercase (a-z), uppercase (A-Z) + specials
    const re = /"([^"]{60,70})"/g;
    let m;
    const candidates = [];
    while ((m = re.exec(text)) !== null) {
        const s = m[1];
        // Must contain sequential digit range and letter ranges
        if (!s.includes('0') || !s.includes('9')) continue;
        if (!s.includes('a') || !s.includes('z')) continue;
        if (!s.includes('A') || !s.includes('Z')) continue;
        // Count unique character types
        const digits = new Set(s.match(/[0-9]/g) || []);
        const lower = new Set(s.match(/[a-z]/g) || []);
        const upper = new Set(s.match(/[A-Z]/g) || []);
        if (digits.size >= 10 && lower.size >= 26 && upper.size >= 26) {
            // Verify all chars are unique (it's a permutation alphabet)
            const unique = new Set(s);
            if (unique.size === s.length) {
                candidates.push({ str: s, index: m.index });
            }
        }
    }
    if (candidates.length === 0) return null;

    // Prefer the one closest to a cipher config pattern
    for (const c of candidates) {
        const nearby = text.slice(Math.max(0, c.index - 5000), Math.min(text.length, c.index + 5000));
        if (/startAt:\d+,length:\d+/.test(nearby) || /encryptText|encrypt\(/.test(nearby)) {
            return c.str;
        }
    }
    // Fallback: return first candidate
    return candidates[0].str;
}

// ─── Config Pattern Matching (ported from userscript) ────────────────────────

function isSignInFlow(ctx) {
    if (/otpLabel:|resendButton:|verify OTP/i.test(ctx)) return false;
    if (/continueBooking:|dateLabel:|timeHeading:|reserving:/.test(ctx)) return false;
    return /signInButton:|passwordLabel:|phoneLabel:|forgotPassword:|noAccount:/.test(ctx);
}

function isReserveSlotFlow(ctx) {
    if (/signInButton:|passwordLabel:|phoneLabel:|forgotPassword:/.test(ctx)) return false;
    return (
        /\/slots\/reserveSlot/.test(ctx) ||
        /continueBooking:|continue-payment|reserving:|Reserving /.test(ctx) ||
        /dateLabel:|timeHeading:/.test(ctx) ||
        /G\(\{c:|mutationFn:\s*[a-zA-Z_$][\w$]*/.test(ctx)
    );
}

// Brace-match a {...} object starting at `open` (which must index a '{'), skipping
// string literals so quotes containing braces can't throw off the depth count.
// Returns { text, end } or null. `end` is the index just past the closing '}'.
function sliceBraceObject(text, open, limit = 20000) {
    let depth = 0, inStr = null;
    for (let i = open; i < text.length && i < open + limit; i++) {
        const ch = text[i];
        if (inStr) { if (ch === '\\') { i++; continue; } if (ch === inStr) inStr = null; continue; }
        if (ch === '"' || ch === "'" || ch === '`') { inStr = ch; continue; }
        if (ch === '{') depth++;
        else if (ch === '}') { depth--; if (depth === 0) return { text: text.slice(open, i + 1), end: i + 1 }; }
    }
    return null;
}

// Read the integer value out of an obfuscated numeric field expression. The current
// bundle wraps startAt/length/version in calls, e.g.:
//   startAt:Number("1")   length:e.AURJO(Number,"27")   version:c[d(713,"j&v5")](_0x7876a8,"2")
// In every variant the REAL value is passed as a QUOTED integer string, so we take the
// last quoted integer (unquoted table indices like 1486/713 are ignored). Older builds
// used a bare literal (startAt:1) — covered by the bare-integer fallback.
function fieldNumber(fieldExpr) {
    if (fieldExpr == null) return NaN;
    const quoted = [...String(fieldExpr).matchAll(/"(\d{1,4})"|'(\d{1,4})'/g)];
    if (quoted.length) { const q = quoted[quoted.length - 1]; return parseInt(q[1] != null ? q[1] : q[2], 10); }
    const bare = String(fieldExpr).match(/-?\d{1,4}/);
    return bare ? parseInt(bare[0], 10) : NaN;
}

function findCipherConfigs(text) {
    // Locate config DEFINITIONS: `NAME={secret:` — an assignment to an object literal
    // whose first field is `secret`. Matches both `const e={secret:…}` and the
    // keyword-less `t={secret:…}`, while excluding destructuring reads like
    // `{secret:r,startAt:o,…}=t` (those have no `NAME=` before the brace).
    const defRe = /([A-Za-z_$][\w$]{0,15})=\{secret:/g;
    const results = [];
    const seen = new Set();
    let m;
    while ((m = defRe.exec(text)) !== null) {
        const keyVar = m[1];
        const braceOpen = text.indexOf('{', m.index);
        if (braceOpen < 0) continue;
        const obj = sliceBraceObject(text, braceOpen);
        if (!obj) continue;
        const objText = obj.text;

        // Split into fields by the fixed field-name markers. This is robust to the commas
        // that now appear INSIDE the wrapped number expressions (e.g. AURJO(Number,"27")).
        const sMatch = objText.match(/secret:([\s\S]*?),startAt:/);
        const aMatch = objText.match(/,startAt:([\s\S]*?),length:/);
        const lMatch = objText.match(/,length:([\s\S]*?),version:/);
        const vMatch = objText.match(/,version:([\s\S]*?)\}$/);
        if (!sMatch || !aMatch || !lMatch || !vMatch) continue;

        const secretExpr = sMatch[1].trim();
        const startAt = fieldNumber(aMatch[1]);
        const length = fieldNumber(lMatch[1]);
        const version = fieldNumber(vMatch[1]);

        if (!Number.isFinite(startAt) || !Number.isFinite(length) || !Number.isFinite(version)) continue;
        if (startAt <= 0 || startAt >= 50 || length <= 0 || length >= 100) continue;
        if (seen.has(m.index)) continue;
        seen.add(m.index);

        // Determine flow from surrounding context
        const ctxStart = Math.max(0, m.index - 3000);
        const ctxEnd = Math.min(text.length, m.index + 12000);
        const ctx = text.slice(ctxStart, ctxEnd);

        let flow = 'unknown';
        if (isSignInFlow(ctx)) flow = 'signin';
        else if (isReserveSlotFlow(ctx)) flow = 'reserve';

        results.push({
            keyVar,
            secretExpr,
            startAt,
            length,
            version,
            flow,
            index: m.index,
            fullMatch: objText,
        });
    }
    return results;
}

// ─── Key Evaluation (vm sandbox) ─────────────────────────────────────────────

function escapeRegExp(s) {
    return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function extractFunctionDef(text, fnName, startPos, endPos) {
    const region = text.slice(startPos, endPos);
    const needle = 'function ' + fnName + '(';
    const idx = region.indexOf(needle);
    if (idx < 0) return '';
    const openBrace = region.indexOf('{', idx);
    if (openBrace < 0) return '';
    let depth = 0;
    for (let i = openBrace; i < region.length; i++) {
        if (region[i] === '{') depth++;
        else if (region[i] === '}') {
            depth--;
            if (depth === 0) return region.slice(idx, i + 1);
        }
    }
    return '';
}

// Extract the LAST `function fnName(...){...}` declaration within `region` (brace-matched).
// "Last" matters because the obfuscator redefines the same short name within a scope and, per
// JS hoisting, the final declaration is the one in effect where the config sits (e.g. `W` is
// declared twice in the config's method; the secret needs the later one).
function extractLastFunctionDef(region, fnName) {
    const needle = 'function ' + fnName + '(';
    const idx = region.lastIndexOf(needle);
    if (idx < 0) return '';
    const openBrace = region.indexOf('{', idx);
    if (openBrace < 0) return '';
    let depth = 0;
    for (let i = openBrace; i < region.length; i++) {
        if (region[i] === '{') depth++;
        else if (region[i] === '}') { depth--; if (depth === 0) return region.slice(idx, i + 1); }
    }
    return '';
}

function stripStringLiterals(source) {
    return String(source)
        .replace(/"(?:\\.|[^"\\])*"/g, '""')
        .replace(/'(?:\\.|[^'\\])*'/g, "''")
        .replace(/`(?:\\.|[^`\\])*`/g, '``');
}

// Callee names in an expression, INCLUDING single-letter names (o(), r(), …). The current
// bundle names its decoders with a single char, which calleeNamesFromExpr (2+ chars) misses.
function calleeNamesLoose(expr) {
    const stripped = stripStringLiterals(expr);
    const names = new Set();
    const re = /\b([A-Za-z_$][\w$]*)\s*\(/g;
    let m;
    while ((m = re.exec(stripped)) !== null) names.add(m[1]);
    return [...names];
}

// All identifiers REFERENCED by an expression — not just the ones being called. The current
// bundle builds the secret as an INDEX into a local object table (e.g. `secret:n[o(191)]`, where
// `const n={...}` is a nearby object literal), so `n` is referenced but never called; a
// callee-only scan misses it and the secret evals with `n` undefined. We skip property accesses
// (`.foo`) and object-literal keys (`foo:`) so only real variable references come back.
function identifiersInExpr(expr) {
    const stripped = stripStringLiterals(expr);
    const names = new Set();
    const re = /[A-Za-z_$][\w$]*/g;
    let m;
    while ((m = re.exec(stripped)) !== null) {
        if (stripped[m.index - 1] === '.') continue;            // property access: x.foo
        if (/^\s*:/.test(stripped.slice(m.index + m[0].length))) continue; // object key: foo:
        names.add(m[0]);
    }
    return [...names];
}

// Extract the LAST `const|let|var NAME=<initializer>` declaration for NAME within `region`,
// returning the whole statement text. The initializer is captured by walking () [] {} depth
// (string-aware) and stopping at the first depth-0 newline / `;` / closing bracket — which is how
// the minified bundle separates statements. Used to pull in local object tables (`const n={...}`)
// that the secret expression indexes into. Returns '' when NAME is not a local var here.
function extractLastVarDecl(region, name) {
    const declRe = new RegExp('\\b(?:const|let|var)\\s+' + escapeRegExp(name) + '\\s*=', 'g');
    let m, last = null;
    while ((m = declRe.exec(region)) !== null) last = m;
    if (!last) return '';
    const start = last.index;
    let i = last.index + last[0].length; // just past the '='
    let depth = 0, inStr = null;
    for (; i < region.length; i++) {
        const ch = region[i];
        if (inStr) { if (ch === '\\') { i++; continue; } if (ch === inStr) inStr = null; continue; }
        if (ch === '"' || ch === "'" || ch === '`') { inStr = ch; continue; }
        if (ch === '(' || ch === '[' || ch === '{') depth++;
        else if (ch === ')' || ch === ']' || ch === '}') { if (depth === 0) break; depth--; }
        else if (depth === 0 && (ch === '\n' || ch === ';')) break;
    }
    return region.slice(start, i);
}

function findLookupTableEnd(text, beforeIdx) {
    const start = Math.max(0, beforeIdx - 150000);
    const region = text.slice(start, beforeIdx);
    const matches = [...region.matchAll(/\}\(([A-Za-z_$][\w$]{1,6})\)/g)];
    if (!matches.length) return null;
    const last = matches[matches.length - 1];
    return {
        end: start + last.index + last[0].length,
        varName: last[1],
    };
}

function calleeNamesFromExpr(expr) {
    const stripped = stripStringLiterals(expr);
    const names = [];
    const re = /\b([A-Za-z_$][\w$]{1,})\s*\(/g;
    let m;
    while ((m = re.exec(stripped)) !== null) {
        names.push(m[1]);
    }
    return [...new Set(names)];
}

function resolveDecoderGraph(text, callees, assignIdx, rot) {
    const fnNames = [];
    const seen = {};
    function add(name) {
        if (!name || seen[name]) return;
        seen[name] = true;
        fnNames.push(name);
    }
    for (const c of callees) add(c);
    if (rot && rot.varName) add(rot.varName);
    const searchStart = Math.max(0, assignIdx - 80000);
    const searchEnd = assignIdx + 25000;
    let changed = true;
    while (changed) {
        changed = false;
        for (const fn of fnNames) {
            const block = extractFunctionDef(text, fn, searchStart, searchEnd);
            if (!block) continue;
            const stripped = stripStringLiterals(block);
            let m;
            const retRe = /\breturn\s+([A-Za-z_$][\w$]{1,})\s*\(/g;
            while ((m = retRe.exec(stripped)) !== null) {
                if (!seen[m[1]]) { add(m[1]); changed = true; }
            }
            const varRe = /\bvar\s+n\s*=\s*([A-Za-z_$][\w$]{1,})\(\)/g;
            while ((m = varRe.exec(stripped)) !== null) {
                if (!seen[m[1]]) { add(m[1]); changed = true; }
            }
        }
    }
    return fnNames;
}

function collectFunctions(text, start, end, fnNames) {
    let out = '';
    const seen = {};
    for (const fn of fnNames) {
        if (seen[fn]) continue;
        const block = extractFunctionDef(text, fn, start, end);
        if (block) {
            seen[fn] = true;
            out += '\n' + block;
        }
    }
    return out;
}

function buildProfileKeyEval(text, keyVar) {
    const configRe = new RegExp(
        'const\\s+' + escapeRegExp(keyVar) +
        '=\\{secret:((?:[^"{}]|"(?:\\\\.|[^"\\\\])*")*?),startAt:(\\d+),length:(\\d+),version:(\\d+)\\}'
    );
    const configMatch = text.match(configRe);
    if (!configMatch) return null;

    const configLine = configMatch[0];
    const secretExpr = configMatch[1].trim();
    const assignIdx = text.indexOf(configLine);
    if (assignIdx < 0) return null;

    const rot = findLookupTableEnd(text, assignIdx);
    if (!rot) return null;

    const fnNames = resolveDecoderGraph(
        text,
        calleeNamesFromExpr(secretExpr),
        assignIdx,
        rot
    );

    // Find the IIFE that sets up the rotation table
    const iifeStart = text.lastIndexOf('!function(e)', rot.end);
    const searchStart = Math.max(0, rot.end - 30000);

    let decStart = -1;
    for (const fn of fnNames) {
        const rel = text.slice(searchStart, rot.end).indexOf('function ' + fn + '(');
        if (rel < 0) continue;
        const pos = searchStart + rel;
        if (decStart < 0 || pos < decStart) decStart = pos;
    }

    let start = iifeStart >= 0 ? iifeStart : Math.max(0, rot.end - 12000);
    if (decStart >= 0 && decStart < start) start = decStart;

    const head = text.slice(start, rot.end);
    const beforeConfig = collectFunctions(text, rot.end, assignIdx, fnNames);
    const tail = collectFunctions(text, assignIdx + configLine.length, assignIdx + configLine.length + 25000, fnNames);

    return (
        head +
        beforeConfig +
        tail +
        '\n' +
        configLine +
        '\nRESULT=' + keyVar + '.secret;\n'
    );
}

/**
 * New approach for bundles where secret is built from many concatenated
 * obfuscated decoder calls (e.g. qV(356)+QV(0,-542)+AV("aXCw",291)+...).
 * Extracts a minimal self-contained section and executes it in a VM
 * function wrapper so that hoisted function declarations are available.
 */
function buildSectionEval(text, keyVar, configIdx) {
    // Step 1: Find the last base string-table getter before configIdx
    // Pattern: function NAME(){(const|var) e=["...obfuscated strings..."
    const searchLimit = Math.max(0, configIdx - 600000);
    const tableRe = /\bfunction\s+([A-Za-z_$][\w$]{0,10})\s*\(\)\s*\{\s*(?:const|var)\s+e\s*=\s*\["[^"]{3,}/g;
    let m;
    let baseTable = null;
    tableRe.lastIndex = searchLimit;
    while ((m = tableRe.exec(text)) !== null) {
        if (m.index >= configIdx) break;
        baseTable = { name: m[1], pos: m.index };
    }
    if (!baseTable) return null;

    // Step 2: Find the earliest code needed before the base table definition.
    // (a) Find wrapper decoders that call the base table by name (before base table pos)
    const baseName = baseTable.name;
    const wrapperRe = new RegExp(
        `\\bfunction\\s+([A-Za-z_$][\\w$]{0,10})\\s*\\(e(?:,t)?\\)\\s*\\{[^}]{0,200}\\b${escapeRegExp(baseName)}\\s*\\(`,
        'g'
    );
    const wrapSearchStart = Math.max(searchLimit, baseTable.pos - 10000);
    const wrapSearchEnd = Math.min(configIdx + 10000, text.length);
    const wrapRegion = text.slice(wrapSearchStart, wrapSearchEnd);
    let earliestWrapperPos = baseTable.pos; // fallback
    wrapperRe.lastIndex = 0;
    while ((m = wrapperRe.exec(wrapRegion)) !== null) {
        const absPos = wrapSearchStart + m.index;
        if (absPos < baseTable.pos && absPos < earliestWrapperPos) {
            earliestWrapperPos = absPos;
        }
    }

    // Step 3: Determine the config object's exact end by brace-matching from configIdx.
    // The current bundle wraps startAt/length/version in obfuscated calls (e.g.
    // startAt:Number("1")), so the old literal-digit regex no longer matches — brace
    // matching is format-agnostic. `configIdx` points at the `keyVar=` assignment, so the
    // object's '{' is a few chars ahead.
    const objOpen = text.indexOf('{', configIdx);
    if (objOpen < 0 || objOpen - configIdx > 40) return null;
    const configObj = sliceBraceObject(text, objOpen);
    if (!configObj) return null;
    const configEnd = configObj.end;
    // Get the config text for callee extraction
    const configMatchText = configObj.text;

    // (b) Find the anti-tamper IIFE that shuffles the string table.
    // Pattern: !function(e){...for(;;)try{...}catch(){...}}(BASENAME)
    // This IIFE must be included because it initializes the string table order.
    // Search in the region between earliestWrapperPos and configIdx.
    const iifeSearchWindow = text.slice(Math.max(searchLimit, earliestWrapperPos - 2000), configIdx);
    const iifeEndPattern = `}(${baseName})`;
    const iifeEndInWindow = iifeSearchWindow.lastIndexOf(iifeEndPattern);
    if (iifeEndInWindow >= 0) {
        // Find the matching !function(e){ opening by scanning backward
        const beforeIifeEnd = iifeSearchWindow.slice(0, iifeEndInWindow);
        const iifeOpenInWindow = beforeIifeEnd.lastIndexOf('!function(e){');
        if (iifeOpenInWindow >= 0) {
            const iifeAbsStart = Math.max(searchLimit, earliestWrapperPos - 2000) + iifeOpenInWindow;
            if (iifeAbsStart < earliestWrapperPos) {
                earliestWrapperPos = iifeAbsStart;
            }
        }
    }

    // Step 4: Extract the core section
    const sectionStart = Math.min(earliestWrapperPos, baseTable.pos);
    let sectionEnd = configEnd;

    // Step 5: Scan FORWARD up to 8000 chars after the config for additional
    // function declarations that the config's secret expression depends on
    // (hoisted functions defined later in the same scope, like JZ/ZZ for VZ)
    // Extract ONLY the secret expression (between "secret:" and ",startAt:")
    // to avoid false callee matches from other parts of the config line.
    const secretExprMatch = configMatchText.match(/secret:([\s\S]*?),startAt:/);
    const secretExprRaw = secretExprMatch ? secretExprMatch[1] : configMatchText;
    const calleesInSecret = calleeNamesFromExpr(secretExprRaw);
    const forwardRegion = text.slice(configEnd, configEnd + 8000);
    for (const callee of calleesInSecret) {
        // Only look for SIMPLE decoder function declarations
        // Pattern: function NAME(e,t){return BASEFN(  or function NAME(e){return BASEFN(
        // This prevents false positives matching callees inside larger function bodies
        const simpleDeclRe = new RegExp(
            `\\bfunction\\s+${escapeRegExp(callee)}\\s*\\(e(?:,t)?\\)\\{return\\s+[A-Za-z_$][\\w$]*\\(`
        );
        const fnDeclMatch = simpleDeclRe.exec(forwardRegion);
        if (fnDeclMatch) {
            // Find the closing brace of this function body using brace counting
            const openBracePos = forwardRegion.indexOf('{', fnDeclMatch.index);
            let depth = 0;
            let closeBracePos = -1;
            for (let i = openBracePos; i < forwardRegion.length; i++) {
                if (forwardRegion[i] === '{') depth++;
                else if (forwardRegion[i] === '}') {
                    depth--;
                    if (depth === 0) { closeBracePos = i; break; }
                }
            }
            const endPos = closeBracePos >= 0 ? closeBracePos + 1 : fnDeclMatch.index + 100;
            const newEnd = configEnd + endPos;
            if (newEnd > sectionEnd) sectionEnd = newEnd;
        }
    }

    const section = text.slice(sectionStart, sectionEnd);
    const resultVar = '__CIPHER_RESULT_' + keyVar + '__';
    return `(function() {\n${section}\nvar ${resultVar} = typeof ${keyVar} !== 'undefined' ? ${keyVar} : null;\nreturn ${resultVar};\n})()`;
}

function parsePlaintextSecret(text, keyVar) {
    const re = new RegExp(
        'const\\s+' + escapeRegExp(keyVar) +
        '=\\{secret:"((?:\\\\.|[^"\\\\])*)",startAt:(\\d+),length:(\\d+),version:(\\d+)\\}'
    );
    const m = text.match(re);
    if (!m) return null;
    try {
        return JSON.parse('"' + m[1] + '"');
    } catch (_) {
        return null;
    }
}

// Per-strategy VM eval budget. vm.runInContext is SYNCHRONOUS — it blocks the whole
// Node main thread for the entire timeout — so this is also the max the event loop can
// freeze on a wedged secret. A real eval finishes in ~25ms (a Strategy-1 *miss* fails
// in ~15ms), so a big ceiling buys nothing: when a section spins (the self-decoding
// for(;;) pattern some bundle versions ship) the old 5000ms burned a full 5s before
// falling through to Strategy 2 — which then produced the key instantly. 1000ms is a
// 40x margin over a real eval while letting a spinning one fail fast.
const SECRET_EVAL_TIMEOUT_MS = 1000;

// ─── Global-decoder secret evaluation (current IVAC obfuscator) ───────────────
// The live bundle builds each secret from method-local decoders (o(),r(),s(),…) that wrap a
// GLOBAL string-array machine: an array function (e.g. WW), RC4 decoders (uW/fW), and a
// self-invoking rotation IIFE `!function(e){…}(WW)` that sorts the array at load. To evaluate
// the secret we assemble a runnable script:
//   [global block: base decoders + array fn + rotation IIFE]
//   + [the config's method-local decoders — LAST definition of each, per JS hoisting]
//   + [nearby local string consts the secret may reference]
//   + return (<secretExpr>)
// Everything is pure/deterministic, so running it reproduces the exact key the site uses.
function buildGlobalDecoderEval(text, configEntry) {
    const { index: configIdx, secretExpr } = configEntry;
    if (!secretExpr) return null;

    // 1. Locate the rotation IIFE `}(ARRAYFN)` and the array function it sorts.
    const rot = findLookupTableEnd(text, configIdx);
    if (!rot) return null;
    const arrayFnPos = text.lastIndexOf(`function ${rot.varName}(`, rot.end);
    if (arrayFnPos < 0) return null;

    // 2. Collect the method-local decoders the secret needs (transitively), taking the LAST
    //    definition of each within the config's method window (JS hoisting: last decl wins,
    //    which is how a name like `W` redefined after the config resolves).
    //    Callee names NOT found in the window are GLOBAL decoders (they live in the block).
    //    The forward edge is capped at the NEXT config definition so we never pull a
    //    neighbouring method's decoders (each method redefines the same short names).
    let winStart = Math.max(0, configIdx - 3500);
    let winEnd = Math.min(text.length, configIdx + 4000);
    // Cap the window START at the current method's start too. Class members reuse the same short
    // decoder names AND can define a `function n(){…}` that would otherwise shadow THIS method's
    // `const n={…}` object table (the secret indexes into the object, not the function). The member
    // boundary is the previous member's close immediately followed by `static`, i.e. `}static`.
    const memberStart = text.lastIndexOf('}static', configIdx);
    if (memberStart >= 0 && memberStart + 1 > winStart) winStart = memberStart + 1;
    // Cap at the config's OWN method close so a neighbouring method's decoders (which reuse
    // the same short names) can't leak in. Methods here are class `static` members, so the
    // boundary is `}static`; also stop at the next config definition as a backstop.
    const memberEnd = text.slice(configIdx).search(/\}\s*static\b/);
    if (memberEnd >= 0) winEnd = Math.min(winEnd, configIdx + memberEnd + 1);
    const nextDef = text.slice(configIdx + 1).search(/[A-Za-z_$][\w$]{0,15}=\{secret:/);
    if (nextDef >= 0) winEnd = Math.min(winEnd, configIdx + 1 + nextDef);
    const win = text.slice(winStart, winEnd);
    // `const/let/var` initializers are NOT hoisted, so the table the secret indexes into must be
    // declared BEFORE the config. Search var-decls only in the pre-config slice so a same-named
    // redeclaration in a LATER method (`const n=gW()`) can't win over this method's `const n={…}`.
    const preWin = win.slice(0, Math.max(0, configIdx - winStart));
    let localDecls = '';
    const collected = new Set();      // local decoder names captured
    const globalRefs = new Set();     // decoder names that are global (defined outside window)
    // Seed with ALL identifiers of the secret (not just callees) so a local table the secret
    // indexes into — e.g. `n` in `secret:n[o(191)]` — is discovered too, not only the decoders
    // it calls.
    const frontier = identifiersInExpr(secretExpr);
    while (frontier.length) {
        const name = frontier.pop();
        if (collected.has(name) || globalRefs.has(name)) continue;
        const decl = extractLastFunctionDef(win, name);
        if (decl) {
            collected.add(name);
            localDecls += '\n' + decl;
            for (const c of calleeNamesLoose(decl)) if (!collected.has(c)) frontier.push(c);
            continue;
        }
        // Not a local function — it may be a local const/let/var the secret references (an object
        // table like `const n={...}`). Capture its initializer and chase the identifiers inside it
        // (its own decoder calls, further tables, …).
        const varDecl = extractLastVarDecl(preWin, name);
        if (varDecl) {
            collected.add(name);
            localDecls += '\n' + varDecl;
            for (const c of identifiersInExpr(varDecl)) if (!collected.has(c)) frontier.push(c);
            continue;
        }
        globalRefs.add(name); // global / absent — resolved in step 3
    }

    // 3. Bound the global block PRECISELY: walk the global decoder graph (base decoders → RC4
    //    decoders → array fn) to find the earliest definition — the start of the decoder
    //    cluster — so the block is exactly [decoders + array fn + rotation IIFE] with no
    //    unrelated prefix (which would execute and throw). End at the rotation IIFE.
    const BUILTINS = new Set(['String', 'Math', 'parseInt', 'parseFloat', 'Array', 'Object', 'RegExp',
        'Error', 'Boolean', 'Number', 'Symbol', 'JSON', 'isNaN', 'isFinite', 'decodeURIComponent',
        'encodeURIComponent', 'if', 'for', 'while', 'return', 'function', 'typeof', 'new', 'void', 'this']);
    const globalNames = new Set([rot.varName]);
    const gFrontier = [...globalRefs];
    while (gFrontier.length) {
        const name = gFrontier.pop();
        if (globalNames.has(name) || BUILTINS.has(name)) continue;
        const pos = text.lastIndexOf(`function ${name}(`, rot.end);
        if (pos < 0) continue;
        globalNames.add(name);
        // Follow callees found in this decoder's EXACT (brace-matched) body only. A fixed-size
        // slice over-reads into whatever follows the function and drags unrelated top-level names
        // (e.g. `Ae`, whose neighbour runs `Se.textContent=…` at load) into the global set — which
        // then pushes blockStart up to module-top code that throws when evaluated.
        const body = extractFunctionDef(text, name, pos, Math.min(text.length, pos + 6000)) || text.slice(pos, pos + 1500);
        for (const c of calleeNamesLoose(body)) {
            if (!globalNames.has(c) && !BUILTINS.has(c)) gFrontier.push(c);
        }
    }
    let blockStart = arrayFnPos;
    for (const name of globalNames) {
        const pos = text.lastIndexOf(`function ${name}(`, rot.end);
        if (pos >= 0 && pos < blockStart) blockStart = pos;
    }
    const globalBlock = text.slice(blockStart, rot.end);

    // 3. Nearest local string-const line (e.g. const e="…",t="…",n="…") the secret may use.
    //    Bound to the current method (winStart) so a NEIGHBOUR method's `const e="…",t="…"` can't
    //    be pulled in and clash with a decoder function of the same name we captured above
    //    (duplicate `const e` + `function e` = a SyntaxError that kills the whole eval).
    const preRegion = text.slice(Math.max(winStart, configIdx - 2500), configIdx);
    const constMatches = preRegion.match(/const [A-Za-z_$][\w$]*="[^"]*"(?:,[A-Za-z_$][\w$]*="[^"]*")*/g);
    let localConsts = constMatches ? constMatches[constMatches.length - 1] : '';
    // Drop any const names we already captured as decoder functions, to be safe against a
    // duplicate-declaration SyntaxError even within a single method.
    if (localConsts) {
        const dupName = [...collected].some(n => new RegExp('(?:^|,)' + escapeRegExp(n) + '=').test(localConsts));
        if (dupName) localConsts = '';
    }

    return `(function(){\n${globalBlock}\n${localConsts}\n${localDecls}\nreturn (${secretExpr});\n})()`;
}

function evaluateSecret(text, configEntry) {
    // Try plaintext first
    const plain = parsePlaintextSecret(text, configEntry.keyVar);
    if (plain) return { key: plain, err: null };

    // Strategy 0 — UNIVERSAL (AST reference-closure). Parse the bundle and follow the secret
    // expression's reference graph to reassemble+run exactly the decoder machine it needs.
    // Layout/renaming independent, so it survives the ~daily re-obfuscation that breaks the
    // position-based heuristics below. See cipherAst.js. Falls through to them if it can't
    // produce a key (parse failure, or a fundamentally new scheme).
    try {
        const astKey = cipherAst.secretFor(text, configEntry);
        if (astKey) return { key: astKey, err: null };
    } catch (e) {
        logger.debug(`[CipherKeys] AST secret eval failed for ${configEntry.keyVar}: ${e.message.slice(0, 140)}`);
    }

    // Strategy A (current bundle): assemble the global string-array decoder machine + the
    // config's method-local decoders, and evaluate the secret expression directly.
    try {
        const gScript = buildGlobalDecoderEval(text, configEntry);
        if (gScript) {
            const sandbox = {
                decodeURIComponent, encodeURIComponent, String, Math, parseInt, parseFloat,
                Array, Object, RegExp, Error, Boolean, Number, Symbol, JSON, isNaN, isFinite,
            };
            const context = vm.createContext(sandbox);
            const result = vm.runInContext(gScript, context, { timeout: SECRET_EVAL_TIMEOUT_MS });
            const key = result == null ? '' : String(result).trim();
            if (key) return { key, err: null };
        }
    } catch (e) {
        logger.debug(`[CipherKeys] Global-decoder eval failed for ${configEntry.keyVar}: ${e.message.slice(0, 120)}`);
    }

    // Strategy 1: Older approach — extract self-contained section and execute as a
    // function wrapper. Handles the previous multi-call concatenated secret format.
    const sectionScript = buildSectionEval(text, configEntry.keyVar, configEntry.index);
    if (sectionScript) {
        try {
            const sandbox = {
                decodeURIComponent,
                encodeURIComponent,
                String,
                Math,
                parseInt,
                parseFloat,
                Array,
                Object,
                RegExp,
                Error,
                Boolean,
                Number,
            };
            const context = vm.createContext(sandbox);
            const result = vm.runInContext(sectionScript, context, { timeout: SECRET_EVAL_TIMEOUT_MS });
            if (result && result.secret) {
                const key = String(result.secret).trim();
                if (key) return { key, err: null };
            }
        } catch (e) {
            logger.debug(`[CipherKeys] Section eval failed for ${configEntry.keyVar}: ${e.message.slice(0, 120)}`);
        }
    }

    // Strategy 2: Legacy approach — single decoder function call (old bundle format)
    const script = buildProfileKeyEval(text, configEntry.keyVar);
    if (!script) return { key: null, err: 'Could not build key eval script for ' + configEntry.keyVar };

    try {
        const sandbox = { RESULT: '' };
        const context = vm.createContext(sandbox);
        vm.runInContext(script, context, { timeout: SECRET_EVAL_TIMEOUT_MS });
        const key = String(sandbox.RESULT || '').trim();
        if (key) return { key, err: null };
        return { key: null, err: 'Key empty after vm eval' };
    } catch (e) {
        return { key: null, err: `vm eval error: ${e.message}` };
    }
}

// ─── Main Pull Function ──────────────────────────────────────────────────────

async function pullCipherKeys(onProgress, ctx) {
    ctx = ctx || getDefaultCtx();
    const progress = onProgress || ((msg) => logger.info(`[CipherKeys] ${msg}`));
    const throwIfAborted = () => { if (ctx.signal && ctx.signal.aborted) throw new Error('aborted'); };

    // Try the LIVE bundle first; if the site is off / Cloudflare 403s / no valid bundle comes
    // back, fall back to the LAST LOCAL bundle (saved on the previous successful pull, or a repo
    // snapshot). This is what keeps the panel working when the site is down.
    let bestText = null;
    let bestUrl = '';
    let bestConfigs = [];
    let bestScore = -1;
    let usedLocalBundle = false;

    try {
        progress('Fetching IVAC website HTML...');
        const html = await fetchWebsiteHtml(ctx);
        throwIfAborted();

        progress('Extracting bundle URLs...');
        const bundleUrls = extractBundleUrls(html);
        if (!bundleUrls.length) {
            throw new Error('No /assets/*.js bundles found on the IVAC website');
        }
        progress(`Found ${bundleUrls.length} bundle(s): ${bundleUrls.map(u => u.split('/').pop()).join(', ')}`);

        // Download every bundle CONCURRENTLY, each on its OWN forked connection so the big
        // main bundle isn't starved by sharing a single HTTP/2 window with the small chunks
        // (that contention is what tripped the 12s body-read deadline). allSettled so one bad
        // chunk can't reject the whole batch. See fetchBundlesParallel for the details.
        progress(`Downloading ${bundleUrls.length} bundle(s) in parallel...`);
        const settled = await fetchBundlesParallel(bundleUrls, ctx);
        throwIfAborted();

        // Score each downloaded bundle and pick the best.
        for (let i = 0; i < settled.length; i++) {
            const url = bundleUrls[i];
            const name = url.split('/').pop();
            const outcome = settled[i];
            if (outcome.status === 'rejected') {
                progress(`Failed to fetch ${name}: ${outcome.reason && outcome.reason.message || outcome.reason}`);
                continue;
            }
            const text = outcome.value.text;
            if (!text || text.length < 1000) continue;

            const configs = findCipherConfigs(text);
            let score = 0;
            if (configs.some(c => c.flow === 'signin')) score += 60;
            if (configs.some(c => c.flow === 'reserve')) score += 60;
            if (text.includes('/auth/sign-in-v2')) score += 10;
            if (text.includes('/slots/reserveSlot')) score += 10;

            if (score > bestScore) {
                bestScore = score;
                bestText = text;
                bestUrl = url;
                bestConfigs = configs;
            }
        }

        if (!bestText) throw new Error('Could not download any valid bundle');
    } catch (liveErr) {
        if (ctx.signal && ctx.signal.aborted) throw liveErr; // a user abort is not a live-failure
        progress(`⚠️ Live bundle unavailable (${liveErr.message}). Falling back to the last local bundle…`);
        const local = loadLocalBundle();
        if (!local || !local.text) {
            throw new Error(`Live fetch failed and no local bundle is cached: ${liveErr.message}`);
        }
        bestText = local.text;
        bestUrl = local.url || 'local';
        bestConfigs = findCipherConfigs(bestText);
        bestScore = -1;
        usedLocalBundle = true;
        progress(`📦 Using last local bundle: ${String(bestUrl).split('/').pop()} (${bestText.length} bytes, ${bestConfigs.length} configs)`);
    }

    // Cache the live bundle so the next pull can fall back to it if the site goes down.
    if (!usedLocalBundle && bestText) {
        try { saveLocalBundle(bestText, bestUrl); progress('💾 Cached this bundle locally for offline fallback.'); }
        catch (e) { /* non-fatal */ }
    }

    progress(`${usedLocalBundle ? 'Local' : 'Best'} bundle: ${String(bestUrl).split('/').pop()} (score: ${bestScore}, configs: ${bestConfigs.length})`);

    // Extract alphabet from bundle
    const extractedAlphabet = findAlphabet(bestText);
    if (extractedAlphabet) {
        progress(`📎 Alphabet extracted: "${extractedAlphabet.slice(0, 20)}..." (${extractedAlphabet.length} chars)`);
    } else {
        progress(`⚠️ Could not extract alphabet from bundle, using current: "${ALPHABET.slice(0, 20)}..." (${ALPHA_LEN} chars)`);
    }

    // Extract the reserve-slot service id (plaintext in the bundle) and persist it to the same
    // config key api.js reads (`ep_reserve_slot_id`), so a rotated slotId is picked up by the
    // normal key pull without any code change — just like the cipher keys.
    const reserveSlotId = extractReserveSlotId(bestText);
    if (reserveSlotId) {
        await setConfig('ep_reserve_slot_id', reserveSlotId);
        progress(`🎫 Reserve slot id extracted: ${reserveSlotId}`);
    } else {
        progress('⚠️ Could not find a reserve-slot id in the bundle (endpoint shape may have changed) — keeping the configured one.');
    }

    // Extract keys from configs
    throwIfAborted();
    let signinResult = null;
    let reserveResult = null;

    let signinConfigs = bestConfigs.filter(c => c.flow === 'signin');
    let reserveConfigs = bestConfigs.filter(c => c.flow === 'reserve');
    const unknownConfigs = bestConfigs.filter(c => c.flow === 'unknown');

    progress(`Found ${bestConfigs.length} cipher config(s): ${bestConfigs.map(c => `${c.keyVar}(${c.flow},startAt=${c.startAt},len=${c.length},v=${c.version})`).join(', ')}`);

    // The flow is detected from UI labels, which change between builds — so a config can land
    // as "unknown". Fall back to the unknown configs PER FLOW (not only when both are empty,
    // which was silently dropping reserve whenever sign-in was detected). Sign-in and reserve
    // almost always have DIFFERENT startAt/length, so for the missing flow prefer an unknown
    // config whose (startAt,length) differs from the one we already have.
    const paramKey = (c) => `${c.startAt}-${c.length}`;
    if (signinConfigs.length === 0 && unknownConfigs.length > 0) {
        const reserveKey = reserveConfigs[0] ? paramKey(reserveConfigs[0]) : null;
        const diff = unknownConfigs.filter(c => paramKey(c) !== reserveKey);
        signinConfigs = diff.length ? [diff[0]] : [unknownConfigs[0]];
        progress(`ℹ️ Sign-in flow not labeled — using unknown config ${signinConfigs[0].keyVar} as sign-in.`);
    }
    if (reserveConfigs.length === 0 && unknownConfigs.length > 0) {
        const signinKey = signinConfigs[0] ? paramKey(signinConfigs[0]) : null;
        // exclude whatever we just used for sign-in, and prefer a different (startAt,length)
        const used = new Set(signinConfigs.map(c => c.keyVar));
        const remaining = unknownConfigs.filter(c => !used.has(c.keyVar));
        const diff = remaining.filter(c => paramKey(c) !== signinKey);
        const pick = diff.length ? diff : remaining;
        if (pick.length) {
            reserveConfigs = pick;
            progress(`ℹ️ Reserve flow not labeled — using unknown config(s) ${pick.map(c => c.keyVar).join(', ')} as reserve.`);
        }
    }

    for (const cfg of signinConfigs) {
        progress(`Evaluating SignIn secret (var: ${cfg.keyVar}, v${cfg.version})...`);
        const result = evaluateSecret(bestText, cfg);
        if (result.key) {
            signinResult = {
                key: result.key,
                startAt: cfg.startAt,
                length: cfg.length,
                version: cfg.version,
            };
            progress(`✅ SignIn key extracted: ${result.key.slice(0, 12)}... (v${cfg.version}, skip=${cfg.startAt}, len=${cfg.length})`);
            break;
        } else {
            progress(`⚠️ SignIn key eval failed for ${cfg.keyVar}: ${result.err}`);
        }
    }

    // Reserve must NOT be the same config as sign-in. Some bundles include a duplicate of the
    // sign-in config that ALSO classifies as "reserve" (identical startAt/length/version/key) —
    // picking it makes reserve == sign-in. Try reserve configs whose params differ from sign-in
    // first; only fall back to an identical one if nothing else evaluates.
    if (signinResult) {
        const sKey = `${signinResult.startAt}-${signinResult.length}-${signinResult.version}`;
        reserveConfigs.sort((a, b) => {
            const aSame = `${a.startAt}-${a.length}-${a.version}` === sKey ? 1 : 0;
            const bSame = `${b.startAt}-${b.length}-${b.version}` === sKey ? 1 : 0;
            return aSame - bSame; // distinct-from-signin configs first
        });
    }

    let reserveFallback = null; // an identical-to-signin reserve, used only if nothing distinct works
    for (const cfg of reserveConfigs) {
        const sameAsSignin = signinResult &&
            cfg.startAt === signinResult.startAt &&
            cfg.length === signinResult.length &&
            cfg.version === signinResult.version;
        progress(`Evaluating Reserve secret (var: ${cfg.keyVar}, v${cfg.version}${sameAsSignin ? ', same params as sign-in' : ''})...`);
        const result = evaluateSecret(bestText, cfg);
        if (result.key) {
            const entry = { key: result.key, startAt: cfg.startAt, length: cfg.length, version: cfg.version };
            if (sameAsSignin && result.key === signinResult.key) {
                // identical to sign-in — remember as last resort, keep looking for a distinct one
                if (!reserveFallback) reserveFallback = entry;
                progress(`↪️ Reserve config ${cfg.keyVar} is identical to sign-in — skipping, looking for a distinct one...`);
                continue;
            }
            reserveResult = entry;
            progress(`✅ Reserve key extracted: ${result.key.slice(0, 12)}... (v${cfg.version}, skip=${cfg.startAt}, len=${cfg.length})`);
            break;
        } else {
            progress(`⚠️ Reserve key eval failed for ${cfg.keyVar}: ${result.err}`);
        }
    }
    if (!reserveResult && reserveFallback) {
        reserveResult = reserveFallback;
        progress(`⚠️ No distinct reserve config found — falling back to the sign-in-identical one (v${reserveFallback.version}, skip=${reserveFallback.startAt}, len=${reserveFallback.length}).`);
    }

    // Current builds ship a SINGLE cipher config shared by both flows (the sign-in and
    // reserve endpoints encrypt with the same secret/params). When only one flow produced a
    // key, mirror it to the other so both cache slots are populated — otherwise the missing
    // flow would fall back to sending the raw token and get rejected.
    if (signinResult && !reserveResult) {
        reserveResult = { ...signinResult };
        progress(`↔️ Only one cipher config found — mirroring sign-in key to reserve (v${signinResult.version}, skip=${signinResult.startAt}, len=${signinResult.length}).`);
    } else if (reserveResult && !signinResult) {
        signinResult = { ...reserveResult };
        progress(`↔️ Only one cipher config found — mirroring reserve key to sign-in (v${reserveResult.version}, skip=${reserveResult.startAt}, len=${reserveResult.length}).`);
    }

    if (!signinResult && !reserveResult) {
        throw new Error('Failed to extract any cipher keys from the bundle');
    }

    // Extract native encryption functions (all algorithms, keyed by version)
    progress('Extracting native encryption functions...');
    const modulesData = extractCipherModules(bestText);
    if (modulesData) {
        const versions = Object.keys(modulesData.modulesByVersion);
        progress(`✅ Extracted native cipher modules for versions: ${versions.join(', ')}` +
            (Object.keys(modulesData.versionMap).length ? '' : ' (dispatcher map not found — used source order)'));
    } else {
        progress('⚠️ Failed to extract native encryption functions from bundle.');
    }

    // Save to DB (including alphabet and native functions)
    progress('Saving to database...');
    await saveToDb(signinResult, reserveResult, bestUrl, extractedAlphabet, modulesData);

    const summary = {
        bundleUrl: bestUrl,
        bundleFile: bestUrl.split('/').pop(),
        signin: signinResult ? {
            ...signinResult,
            algorithm: `Native (v${signinResult.version})`,
            keyPreview: signinResult.key.slice(0, 12) + '...',
        } : null,
        reserve: reserveResult ? {
            ...reserveResult,
            algorithm: `Native (v${reserveResult.version})`,
            keyPreview: reserveResult.key.slice(0, 12) + '...',
        } : null,
        pulledAt: cache.pulledAt,
        alphabet: ALPHABET,
        alphabetLength: ALPHA_LEN,
        reserveSlotId: reserveSlotId || null,
    };

    progress('✅ Pull complete!');
    return summary;
}

// ─── Auto-Pull Controller ─────────────────────────────────────────────────────
//
// The cipher bundle server frequently answers 403 right after a new build is
// deployed (the browser may already get 200, but the /assets/*.js bundle stays
// locked for ~30–60s). This controller keeps retrying pullCipherKeys() on an
// interval until it succeeds, with a manual stop. It runs in the background so
// the HTTP request that starts it returns immediately; progress + state changes
// are pushed out through the `emit` callback (wired to socket.io in server.js).

// ─── Auto-pull interval (edit here to decide) ─────────────────────────────────
// Gap BETWEEN attempts, in milliseconds: one pull finishes → wait this long → the
// next pull starts. This is NOT a request timeout (each pull already has its own
// fetch timeouts); it only controls how hard we poll the bundle server while it's
// still 403'ing after a fresh deploy.
//   • Lower  → grab the new keys sooner, but more requests (higher 403/429 risk).
//   • Higher → gentler on the server, but you may lag the site coming back online
//              by up to this much.
// Reference points:
//   0     → no gap; loop straight into the next attempt (most aggressive)
//   1000  → ~1 pull/sec (current default)
//   5000  → gentle background polling
// The dashboard can still override this per run by sending `intervalMs` in the
// /api/cipher/auto-pull/start request body; this is only the fallback default.
const DEFAULT_AUTOPULL_INTERVAL_MS = 1000;

const autoPull = {
    running: false,
    stopRequested: false,
    attempts: 0,
    startedAt: null,
    lastAttemptAt: null,
    lastError: null,
    lastSuccessAt: null,
    intervalMs: DEFAULT_AUTOPULL_INTERVAL_MS,
    maxAttempts: 0, // 0 = unlimited
    workers: 1,     // number of parallel pull workers in the current run
};

// The live worker pool for the current auto-pull run (null when idle). Holds each
// worker's "active attempt" slot so stop/win can abort every in-flight request and
// close every session immediately. See startAutoPull().
let _pool = null;

// Hide proxy credentials in logs: protocol://user:pass@host:port → protocol://host:port
function _maskProxy(u) {
    if (!u) return 'direct';
    return String(u).replace(/\/\/[^@/]*@/, '//');
}

// Local wall-clock stamp "HH:MM:SS" for the dashboard Pull Progress panel, so each
// worker/attempt line shows its time to the second. (The console copy is already
// timestamped by winston.)
function _nowHms() {
    const d = new Date();
    const p = (n) => String(n).padStart(2, '0');
    return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function getAutoPullStatus() {
    return {
        running: autoPull.running,
        attempts: autoPull.attempts,
        startedAt: autoPull.startedAt,
        lastAttemptAt: autoPull.lastAttemptAt,
        lastError: autoPull.lastError,
        lastSuccessAt: autoPull.lastSuccessAt,
        intervalMs: autoPull.intervalMs,
        maxAttempts: autoPull.maxAttempts,
        workers: autoPull.workers,
    };
}

function stopAutoPull() {
    if (!autoPull.running) return false;
    autoPull.stopRequested = true;
    // Cancel every in-flight worker attempt immediately: abort its request signal and
    // close its session so a stopped pool dies within a request round-trip, not after
    // waiting out timeouts.
    if (_pool) {
        _pool.stopRequested = true;
        for (const a of _pool.active) {
            if (!a) continue;
            try { a.controller.abort(); } catch (e) { /* ignore */ }
            try { ctxClose(a.ctx); } catch (e) { /* ignore */ }
        }
    }
    return true;
}

function _sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Begin retrying pullCipherKeys() until it succeeds or is stopped — using a POOL of
 * `workers` parallel workers. Each worker retries independently, and EACH attempt goes
 * through a randomly-chosen active proxy (or direct when none are configured). The first
 * worker to extract the cipher info wins; the moment it does, every other worker is
 * aborted immediately (in-flight requests cancelled + sessions closed).
 *
 * @param {object} callbacks  { emit: (event) => void } — event has a `type`
 *        ('started'|'progress'|'attempt-failed'|'success'|'stopped') plus the
 *        current auto-pull status fields, and (for success) a `summary`.
 * @param {object} options    { intervalMs, maxAttempts, workers }
 * @returns {object} the initial status (so the caller can return it synchronously)
 */
function startAutoPull(callbacks = {}, options = {}) {
    const emit = typeof callbacks.emit === 'function' ? callbacks.emit : () => {};

    if (autoPull.running) {
        return { started: false, reason: 'Auto-pull is already running', ...getAutoPullStatus() };
    }

    autoPull.running = true;
    autoPull.stopRequested = false;
    autoPull.attempts = 0;
    autoPull.startedAt = new Date().toISOString();
    autoPull.lastAttemptAt = null;
    autoPull.lastError = null;
    autoPull.lastSuccessAt = null;
    // Default gap between attempts (one finishes, wait, the next starts). Edit the
    // DEFAULT_AUTOPULL_INTERVAL_MS constant above to change the fallback. An explicit
    // 0 is honored (no gap) — only a blank/invalid value falls back to the default.
    const _reqInterval = parseInt(options.intervalMs, 10);
    autoPull.intervalMs = Number.isFinite(_reqInterval) ? Math.max(0, _reqInterval) : DEFAULT_AUTOPULL_INTERVAL_MS;
    autoPull.maxAttempts = Math.max(0, parseInt(options.maxAttempts, 10) || 0);
    // Requested worker count — clamped to a sane ceiling; may drop to 1 below if there
    // are no active proxies (multiple workers from the SAME direct IP buys nothing).
    let workers = Math.max(1, Math.min(20, parseInt(options.workers, 10) || 1));
    autoPull.workers = workers;

    const send = (type, extra = {}) => emit({ type, ...getAutoPullStatus(), ...extra });
    const progress = (message) => {
        logger.info(`[CipherKeys] ${message}`);
        // Prefix a HH:MM:SS stamp on the dashboard copy so the Pull Progress panel shows
        // the timing of each worker/attempt (the console copy is already timestamped by winston).
        send('progress', { message: `[${_nowHms()}] ${message}` });
    };

    const pool = { stopRequested: false, done: false, active: [] };
    _pool = pool;

    // Bootstrap asynchronously so we can await the proxy list before spawning workers,
    // while startAutoPull() still returns the initial status synchronously.
    (async () => {
        // Load the active proxy list. Each attempt picks one at RANDOM (collisions on the
        // same proxy are acceptable). Normalize with api.js's formatProxyUrl — required
        // lazily to avoid the api.js↔cipherKeys circular require at module load.
        let proxyUrls = [];
        try {
            const rows = await getAllProxies();
            let formatProxyUrl = (p) => p;
            try { formatProxyUrl = require('./api').formatProxyUrl || formatProxyUrl; } catch (e) { /* ignore */ }
            proxyUrls = (rows || [])
                .filter(r => Number(r.is_active) === 1 && r.proxy_url)
                .map(r => formatProxyUrl(r.proxy_url))
                .filter(Boolean);
        } catch (e) {
            progress(`⚠️ Failed to load proxy list (${e.message}); running direct.`);
        }

        if (proxyUrls.length === 0) {
            workers = 1;
            autoPull.workers = 1;
            progress('ℹ️ No active proxies — running a single direct worker.');
        }

        send('started');
        progress(`▶️ Auto-pull started with ${workers} worker(s)` +
            `${proxyUrls.length ? ` over ${proxyUrls.length} proxy(ies)` : ' (direct)'}, ` +
            `${autoPull.intervalMs > 0 ? `${Math.round(autoPull.intervalMs / 1000)}s between attempts` : 'no delay between attempts'}` +
            `${autoPull.maxAttempts ? `, max ${autoPull.maxAttempts} attempts` : ''}.`);

        const pickProxy = () => proxyUrls.length ? proxyUrls[Math.floor(Math.random() * proxyUrls.length)] : null;

        const runWorker = async (i) => {
            const label = `W${i + 1}`;
            const wprogress = (m) => progress(`[${label}] ${m}`);

            while (!pool.done && !pool.stopRequested) {
                if (autoPull.maxAttempts > 0 && autoPull.attempts >= autoPull.maxAttempts) break;

                const attemptNo = ++autoPull.attempts;
                autoPull.lastAttemptAt = new Date().toISOString();

                const proxyUrl = pickProxy();
                const controller = new AbortController();
                const ctx = makePullContext({ proxyUrl, httpVersion: 'h2', signal: controller.signal, label });
                pool.active[i] = { controller, ctx };

                wprogress(`🔁 Attempt #${attemptNo} via ${_maskProxy(proxyUrl)}...`);

                try {
                    const summary = await pullCipherKeys(wprogress, ctx);
                    // Someone else already won while we were finishing — discard quietly.
                    if (pool.done) { ctxClose(ctx); return; }

                    // Claim the win and stop every other worker AS FAST AS POSSIBLE.
                    pool.done = true;
                    autoPull.lastError = null;
                    autoPull.lastSuccessAt = new Date().toISOString();
                    wprogress(`✅ Auto-pull succeeded on attempt #${attemptNo}.`);
                    for (const a of pool.active) {
                        if (!a || a.ctx === ctx) continue;
                        try { a.controller.abort(); } catch (e) { /* ignore */ }
                        try { ctxClose(a.ctx); } catch (e) { /* ignore */ }
                    }
                    ctxClose(ctx);
                    autoPull.running = false;
                    send('success', { summary });
                    return;
                } catch (e) {
                    ctxClose(ctx);
                    // Aborted (lost the race / stopped) — leave silently, no failure log.
                    if (pool.done || pool.stopRequested || (ctx.signal && ctx.signal.aborted)) return;
                    autoPull.lastError = e.message;
                    wprogress(`⚠️ Attempt #${attemptNo} failed: ${e.message}`);
                    send('attempt-failed', { error: e.message });
                }

                if (pool.done || pool.stopRequested) return;

                // Optional gap before this worker's next attempt (short slices so a
                // stop/win is honored quickly).
                if (autoPull.intervalMs > 0) {
                    const waitUntil = Date.now() + autoPull.intervalMs;
                    while (Date.now() < waitUntil && !pool.done && !pool.stopRequested) {
                        await _sleep(Math.min(500, Math.max(0, waitUntil - Date.now())));
                    }
                }
            }
        };

        try {
            await Promise.all(Array.from({ length: workers }, (_, i) => runWorker(i)));
        } catch (e) {
            // Defensive — worker errors are caught inside runWorker.
            autoPull.lastError = e.message;
            logger.error(`[CipherKeys] Auto-pull pool crashed: ${e.message}`);
        } finally {
            _pool = null;
            if (autoPull.running) {
                autoPull.running = false;
                if (!pool.done) {
                    if (autoPull.maxAttempts > 0 && autoPull.attempts >= autoPull.maxAttempts && !pool.stopRequested) {
                        progress(`🛑 Reached max attempts (${autoPull.maxAttempts}). Stopping.`);
                    }
                    progress('🛑 Auto-pull stopped.');
                    send('stopped');
                }
            }
        }
    })();

    return { started: true, ...getAutoPullStatus() };
}

// ─── Status / Tester ─────────────────────────────────────────────────────────

function getCachedCipherInfo() {
    return {
        signin: cache.signin ? {
            keyPreview: cache.signin.key.slice(0, 12) + '...',
            keyLength: cache.signin.key.length,
            startAt: cache.signin.startAt,
            length: cache.signin.length,
            version: cache.signin.version,
            algorithm: `Native (v${cache.signin.version})`,
        } : null,
        reserve: cache.reserve ? {
            keyPreview: cache.reserve.key.slice(0, 12) + '...',
            keyLength: cache.reserve.key.length,
            startAt: cache.reserve.startAt,
            length: cache.reserve.length,
            version: cache.reserve.version,
            algorithm: `Native (v${cache.reserve.version})`,
        } : null,
        bundleUrl: cache.bundleUrl,
        bundleFile: cache.bundleUrl ? cache.bundleUrl.split('/').pop() : null,
        pulledAt: cache.pulledAt,
        alphabet: ALPHABET,
        alphabetLength: ALPHA_LEN,
        hasKeys: !!(cache.signin || cache.reserve),
        hasNativeFunctions: Object.keys(cache.nativeByVersion).length > 0,
        nativeVersions: Object.keys(cache.nativeByVersion),
        versionMap: cache.versionMap,
    };
}

function testEncrypt(token, flow) {
    const params = flow === 'reserve' ? cache.reserve : cache.signin;
    if (!params || !params.key) {
        return { error: `No cached keys for flow "${flow}". Pull keys first.` };
    }
    const mod = getNativeForVersion(params.version);
    if (!mod) {
        return { error: `No native module for version ${params.version}. Pull keys first.` };
    }
    try {
        const encrypted = mod.encryptText(token, params.key, params.startAt, params.length);
        return {
            input: token,
            output: encrypted,
            flow,
            params: {
                keyPreview: params.key.slice(0, 12) + '...',
                startAt: params.startAt,
                length: params.length,
                version: params.version,
                algorithm: `Native`,
                alphabet: ALPHABET,
                alphabetLength: ALPHA_LEN,
            },
        };
    } catch (e) {
        return { error: `Native encryption failed: ${e.message}` };
    }
}

function testDecrypt(token, flow) {
    const params = flow === 'reserve' ? cache.reserve : cache.signin;
    if (!params || !params.key) {
        return { error: `No cached keys for flow "${flow}". Pull keys first.` };
    }
    const mod = getNativeForVersion(params.version);
    if (!mod) {
        return { error: `No native module for version ${params.version}. Pull keys first.` };
    }
    try {
        const decrypted = mod.decryptText(token, params.key, params.startAt, params.length);
        return {
            input: token,
            output: decrypted,
            flow,
            params: {
                keyPreview: params.key.slice(0, 12) + '...',
                startAt: params.startAt,
                length: params.length,
                version: params.version,
                algorithm: `Native`,
                alphabet: ALPHABET,
                alphabetLength: ALPHA_LEN,
            },
        };
    } catch (e) {
        return { error: `Native decryption failed: ${e.message}` };
    }
}

// ─── Exports ─────────────────────────────────────────────────────────────────

module.exports = {
    loadFromDb,
    pullCipherKeys,
    startAutoPull,
    stopAutoPull,
    getAutoPullStatus,
    getCachedCipherInfo,
    encryptCaptcha,
    testEncrypt,
    testDecrypt,
    closeCipherSession,
    // exposed for offline testing/diagnostics
    _internals: { findCipherConfigs, evaluateSecret, extractCipherModules, loadLocalBundle, saveLocalBundle, findAlphabet, extractReserveSlotId },
};
