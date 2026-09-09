/**
 * recipeBrowser.js — shared hardened-Chrome launcher for the Recipe Learner / signer.
 *
 * Reuses the SAME engine as the captcha solver (puppeteer-real-browser via rebrowser),
 * which patches the CDP leaks Turnstile scores as "bot". Two jobs:
 *   1. Load the live IVAC site so its OWN JavaScript runs in the real environment it
 *      expects (window/document/crypto/webpack) — impossible in a bare Node vm.
 *   2. Reach into the site's webpack module registry so we can call the site's OWN pure
 *      functions directly (e.g. the cipher `encryptText`) instead of re-implementing or
 *      regex-slicing them. This self-updates every time the site re-obfuscates.
 *
 * The heavy request-shape learning (URLs, rotating header/body keys) lives in
 * recipeLearner.js, which drives the `page` this module hands back and intercepts the
 * real requests over CDP.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const WEBSITE_URL = 'https://appointment.ivacbd.com';

// A throwaway Chrome profile per launch, so every run starts as a FIRST-TIME visitor: no cookies,
// no localStorage (the SPA's `auth-storage` in particular), no service worker, no cached bundle.
// Reusing a profile is what makes a second probe skip the login page or replay a stale bundle.
const PROFILE_PREFIX = 'ivac-probe-profile-';

function makeFreshProfileDir() {
    sweepOldProfiles(); // a run that couldn't unlock its dir on exit gets cleaned up here
    const dir = path.join(os.tmpdir(), `${PROFILE_PREFIX}${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
    try { fs.mkdirSync(dir, { recursive: true }); } catch (e) { return null; }
    return dir;
}

// Delete leftover probe profiles from earlier runs (older than 10 min, so a concurrent probe's
// live profile is never touched). Best-effort: anything still locked is retried next time.
function sweepOldProfiles(maxAgeMs = 10 * 60 * 1000) {
    try {
        const tmp = os.tmpdir();
        for (const name of fs.readdirSync(tmp)) {
            if (!name.startsWith(PROFILE_PREFIX)) continue;
            const full = path.join(tmp, name);
            try {
                if (Date.now() - fs.statSync(full).mtimeMs < maxAgeMs) continue;
                fs.rmSync(full, { recursive: true, force: true });
            } catch (e) { /* locked or gone — skip */ }
        }
    } catch (e) { /* temp unreadable — non-fatal */ }
}

// Prefer Puppeteer's bundled Chrome-for-Testing (Turnstile scores it best — same reason
// server.js's resolveSolverChromePath() prefers it); fall back to an installed Chrome/Edge.
let _cachedChromePath;
function resolveChromePath() {
    if (_cachedChromePath !== undefined) return _cachedChromePath;
    try {
        const bundled = require('puppeteer').executablePath();
        if (bundled && fs.existsSync(bundled)) { _cachedChromePath = bundled; return _cachedChromePath; }
    } catch (e) { /* fall through */ }
    const candidates = [];
    if (process.platform === 'win32') {
        const pf = process.env['ProgramFiles'] || 'C:\\Program Files';
        const pf86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';
        const local = process.env['LOCALAPPDATA'];
        candidates.push(
            `${pf}\\Google\\Chrome\\Application\\chrome.exe`,
            `${pf86}\\Google\\Chrome\\Application\\chrome.exe`,
            local && `${local}\\Google\\Chrome\\Application\\chrome.exe`,
            `${pf86}\\Microsoft\\Edge\\Application\\msedge.exe`,
            `${pf}\\Microsoft\\Edge\\Application\\msedge.exe`
        );
    } else if (process.platform === 'darwin') {
        candidates.push(
            '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
            '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'
        );
    } else {
        candidates.push('/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser');
    }
    for (const c of candidates) { if (c && fs.existsSync(c)) { _cachedChromePath = c; return _cachedChromePath; } }
    _cachedChromePath = null;
    return _cachedChromePath;
}

// In-page bootstrap installed once per page load. Everything here runs INSIDE the site's
// own window, so it sees the real webpack runtime. Kept as a plain function serialized to
// the page (no closure over Node scope) via page.evaluate.
function __installRecipeHook() {
    if (window.__recipe && window.__recipe.ready) return true;
    const R = { ready: false, req: null, cipher: null };

    // Grab __webpack_require__ by pushing an empty chunk whose runtime callback receives it.
    // The chunk-array global name is build-specific, so find it by prefix.
    try {
        const key = Object.keys(window).find((k) => k.startsWith('webpackChunk'));
        if (key && Array.isArray(window[key])) {
            let req;
            window[key].push([['__recipe_' + Math.random().toString(36).slice(2)], {}, (r) => { req = r; }]);
            R.req = req || null;
        }
    } catch (e) { /* no webpack — R.req stays null */ }

    // Find a module whose exports contain a function of the given name (e.g. encryptText).
    // 1) scan already-instantiated modules (req.c); 2) if none, scan factory sources (req.m)
    // for the name, require just those ids (side-effect-guarded), then re-scan.
    // Collect EVERY module whose exports contain a function named fnName. The site ships one
    // cipher module PER version (each exports its own encryptText), so callers that must hit a
    // specific algorithm try them all. 1) instantiate any lazy factory whose source mentions
    // the name; 2) return all instantiated exports carrying it.
    R.findAllExports = function (fnName) {
        const req = R.req;
        if (!req) return [];
        const factories = req.m || {};
        for (const id in factories) {
            let src = '';
            try { src = String(factories[id]); } catch (e) { continue; }
            if (src.indexOf(fnName) === -1) continue;
            try { req(id); } catch (e) { /* forcing a lazy module can throw; ignore */ }
        }
        const out = [];
        const cache = req.c || req.cache || {};
        for (const id in cache) {
            try {
                const ex = cache[id] && cache[id].exports;
                if (ex && typeof ex[fnName] === 'function') out.push(ex);
            } catch (e) { /* getters can throw */ }
        }
        return out;
    };

    R.findExport = function (fnName) {
        const all = R.findAllExports(fnName);
        return all.length ? all[0] : null;
    };

    R.ready = true;
    window.__recipe = R;
    return true;
}

class RecipeBrowser {
    constructor(browser, page, log, profileDir = null) {
        this.browser = browser;
        this.page = page;
        this.log = log || (() => {});
        this.profileDir = profileDir; // throwaway profile to delete on close (null = not ours)
    }

    // Wipe every trace of a previous session: cookies, cache, and all origin storage
    // (localStorage / sessionStorage / IndexedDB / service workers). A fresh profile already
    // starts clean — this also covers re-using one page across several walks.
    async resetState(origin = WEBSITE_URL) {
        try {
            const client = await this.page.target().createCDPSession();
            await client.send('Network.clearBrowserCookies').catch(() => {});
            await client.send('Network.clearBrowserCache').catch(() => {});
            await client.send('Storage.clearDataForOrigin', {
                origin,
                storageTypes: 'all',
            }).catch(() => {});
            await client.detach().catch(() => {});
        } catch (e) {
            this.log(`state reset skipped: ${e.message}`);
        }
        // Belt-and-braces: clear the JS-visible stores if we're already on a page.
        try {
            await this.page.evaluate(() => {
                try { localStorage.clear(); } catch (e) {}
                try { sessionStorage.clear(); } catch (e) {}
            });
        } catch (e) { /* no page loaded yet — nothing to clear */ }
    }

    async goto(url = WEBSITE_URL, opts = {}) {
        await this.page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000, ...opts });
    }

    // Install the webpack hook in the current page. Call after the SPA's main chunk loaded.
    async installHook() {
        return await this.page.evaluate(__installRecipeHook);
    }

    // Call the site's OWN function `fnName` (found via the webpack registry) with `args`.
    // Returns { ok, value } or { ok:false, error }. Retries the hook install once in case
    // the chunk that defines the function loaded after the first install.
    async callSiteFunction(fnName, args = []) {
        for (let attempt = 0; attempt < 2; attempt++) {
            await this.installHook();
            const res = await this.page.evaluate((name, a) => {
                try {
                    const R = window.__recipe;
                    if (!R || !R.req) return { ok: false, error: 'no-webpack-runtime' };
                    const ex = R.findExport(name);
                    if (!ex) return { ok: false, error: 'export-not-found' };
                    return { ok: true, value: ex[name](...a) };
                } catch (e) { return { ok: false, error: String(e && e.message || e) }; }
            }, fnName, args);
            if (res.ok || res.error !== 'export-not-found') return res;
            await this.page.waitForTimeout ? this.page.waitForTimeout(800) : new Promise((r) => setTimeout(r, 800));
        }
        return { ok: false, error: 'export-not-found' };
    }

    // Call `fnName` on EVERY module that exports it, returning all successful return values.
    // Used to verify against the site's cipher when the right version's module is ambiguous.
    async callSiteFunctionAll(fnName, args = []) {
        await this.installHook();
        return await this.page.evaluate((name, a) => {
            const out = [];
            try {
                const R = window.__recipe;
                if (!R || !R.req) return out;
                for (const ex of R.findAllExports(name)) {
                    try { out.push(ex[name](...a)); } catch (e) { /* skip a throwing module */ }
                }
            } catch (e) { /* ignore */ }
            return out;
        }, fnName, args);
    }

    // Convenience: call the site's cipher exactly as the site calls it.
    async encryptWithSite(token, secret, startAt, length) {
        return await this.callSiteFunction('encryptText', [token, secret, startAt, length]);
    }

    // Every site cipher module's encryptText output for these inputs (one per version).
    async encryptWithSiteAll(token, secret, startAt, length) {
        return await this.callSiteFunctionAll('encryptText', [token, secret, startAt, length]);
    }

    // Does the loaded bundle expose the cipher yet? (Used to decide when to walk on.)
    async hasCipher() {
        const r = await this.callSiteFunction('encryptText', ['__probe__', '', 0, 0]).catch(() => ({ ok: false }));
        return !!(r && r.ok);
    }

    async close() {
        try { await this.browser.close(); } catch (e) { /* already gone */ }
        // Remove the throwaway profile so the next run can't inherit anything from this one.
        // Chrome releases its file locks a moment after exit, so retry briefly before giving up
        // (a leftover dir is harmless — the next launch sweeps it — but keep temp tidy).
        if (this.profileDir) {
            const dir = this.profileDir;
            for (let i = 0; i < 5; i++) {
                try { fs.rmSync(dir, { recursive: true, force: true }); break; }
                catch (e) { await new Promise((r) => setTimeout(r, 400)); }
            }
        }
    }
}

// Launch a hardened Chrome, ready to load the IVAC site. `proxy` is the puppeteer-real-browser
// proxy object { host, port, username, password } or undefined for a direct/proxyless launch.
async function launchRecipeBrowser({ proxy = null, headless = false, log = () => {}, freshProfile = true } = {}) {
    const { connect } = require('puppeteer-real-browser');
    // Fresh throwaway profile by default → every launch is a first-time visit (no stale
    // auth-storage / cookies / cached bundle from the previous run).
    const profileDir = freshProfile ? makeFreshProfileDir() : null;
    if (profileDir) log(`Using a fresh browser profile (first-time state): ${profileDir}`);
    const { browser, page } = await connect({
        headless,
        // HARD OFF — deliberately not configurable. puppeteer-real-browser's turnstile helper
        // runs a loop that, once a second forever, blind-clicks the CENTRE of *any* childless
        // <div> between 290-310px wide (see node_modules/puppeteer-real-browser/lib/cjs/module/
        // turnstile.js). That steals focus mid-typing and randomly clicks unrelated UI, which
        // makes the form impossible to fill. The operator solves the captcha themselves; the
        // walk waits for it via SiteDriver.captchaSolved().
        turnstile: false,
        customConfig: { chromePath: resolveChromePath() || undefined, userDataDir: profileDir || undefined },
        proxy: proxy || undefined,
        connectOption: { defaultViewport: null },
        args: [
            '--ignore-certificate-errors',
            '--window-size=1200,900',
            '--max-active-webgl-contexts=100',
        ],
    });
    return new RecipeBrowser(browser, page, log, profileDir);
}

module.exports = { launchRecipeBrowser, RecipeBrowser, resolveChromePath, WEBSITE_URL, sweepOldProfiles };
