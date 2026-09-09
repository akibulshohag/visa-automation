/**
 * bundleProbe.js — learns EVERY request the site would send by running the site's OWN bundle
 * offline, with the network faked, and reading what the bundle TRIES to send.
 *
 * Why this instead of the Recipe Learner (recipeLearner.js):
 *   The learner drives the LIVE site and only captures a step once the real server accepts the
 *   previous one — so if slots are gone you can NEVER reach reserve/payment and never learn them.
 *   It also can't read values the bundle computes at runtime: in the current bundle the header
 *   values are produced by string-rotation decoders, e.g.
 *       Jh.post("/auth/v23-sign-in", body, { headers:{ "x-sec-navigation-state": r[o(0,-158)] }})
 *   `r[o(0,-158)]` only becomes a real value AFTER the code runs — no regex can lift it out.
 *
 * The fix (what this file does):
 *   1. Load the real site so its bundle executes in the environment it expects (window / webpack
 *      / crypto / the axios instance `Jh` with its baseURL and its cipher `encryptText`).
 *   2. Turn the network OFF for the API via CDP request interception: for every XHR/fetch the
 *      bundle makes to an API path we CAPTURE the fully-built request (final absolute URL, all
 *      deobfuscated headers, the ciphered body) and RETURN A SYNTHETIC SUCCESS instead of hitting
 *      the server. The synthetic success makes the SPA advance to the next screen, so a single
 *      offline walk yields sign-in → OTP → upload → reserve → payment with NO live slot.
 *   3. Dump every captured request. That dump is the "all info" needed to rebuild each request:
 *      url, method, headers, body — straight from the bundle, immune to weekly renames.
 *
 * Non-API traffic (the HTML, JS, CSS, fonts, and the Cloudflare Turnstile challenge) is let
 * through untouched so the page actually loads and the widgets work.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { launchRecipeBrowser, WEBSITE_URL } = require('./recipeBrowser');
const { SiteDriver, withRetry, sleep } = require('./recipeDriver');
const { _internals } = require('./recipeLearner');
const { logger } = require('./database');

const matchStep = _internals.matchStep;
const splitUrl = _internals.splitUrl;

// A request is an API call we want to capture+fake when it is an XHR/fetch AND its path looks
// like one of the backend routes. Deliberately broad (matches by stem) so a renamed path is
// still caught. Everything else (document, scripts, styles, images, fonts, Turnstile) is let
// through so the page loads and the captcha widget can run.
const API_PATH_RE = /\/(?:v\d+\/)?(?:auth|otp|file|files|slots?|payment|appointment|appointments|invoice|high-commissions?|ivac-centers?|booking|missions?)\b/i;
const THIRD_PARTY_RE = /challenges\.cloudflare\.com|fonts\.(?:googleapis|gstatic)\.com|google-analytics|googletagmanager|hotjar|sentry|facebook|doubleclick/i;

function isApiRequest(url, resourceType) {
    if (resourceType !== 'xhr' && resourceType !== 'fetch') return false;
    if (THIRD_PARTY_RE.test(url)) return false;
    try {
        const u = new URL(url);
        return API_PATH_RE.test(u.pathname);
    } catch (e) {
        return API_PATH_RE.test(url);
    }
}

// ─── Synthetic responses ─────────────────────────────────────────────────────
// Just enough shape for the SPA to treat the call as a success and move to the next screen.
// The envelope is the site's own `{ statusCode, message, data }`; we add a few alias keys
// (status/code/success) so whichever the bundle checks, it passes. `data` carries the handful
// of fields the next screen reads (requestId after sign-in, a token after OTP, an applicant row
// for the upload screen, …). These are GUESSES refined by watching the console on a live run —
// when a screen errors on a missing field, add it here.

function uuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
        const r = (Math.random() * 16) | 0;
        return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
}

// A structurally-valid JWT (header.payload.signature, base64url) so any jwt-decode in the bundle
// doesn't throw when it reads the token we hand back after OTP verify.
function fakeJwt() {
    const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const now = Math.floor(Date.now() / 1000);
    return `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ sub: '1', userId: 1, iat: now, exp: now + 3600 })}.cHJvYmU`;
}

// The site's real envelope: { data, statusCode, message, successFlag, serverTime }. Matching it
// exactly (esp. `successFlag` and the real data field names) is what makes the SPA accept the
// synthetic response and advance. `status` is the HTTP status for request.respond().
function envelope(data, statusCode = 200) {
    return { status: statusCode, json: { data, statusCode, message: 'Success', successFlag: true, serverTime: new Date().toISOString() } };
}

// A minimal valid one-page PDF, used to feed the upload step when the caller provides no file.
const MIN_PDF = Buffer.from(
    '%PDF-1.1\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n' +
    '2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n' +
    '3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 300 144]>>endobj\n' +
    'trailer<</Root 1 0 R>>\n%%EOF\n', 'utf8');

// Walk progress, so the file-confirmation flags advance and the stepper guards let us into the
// later pages. Flipped by the walk as each step is captured.
const PROGRESS = { uploaded: false, missionSelected: false, reserved: false, paid: false };

// Stable session-wide ids so cross-call references line up (the appointmentId the booking-config
// returns is the same one the SPA carries into reserve/payment). Regenerated per probe run.
const SESSION = {
    commissionId: '180847cf-bd6d-4a34-8347-57a344746b02',
    centerId: '8acea244-6e84-471a-ac17-e2823baccc23',
    appointmentId: 'c329c9d8-968b-4a64-8018-af6482759830',
    requestId: uuid(),
    dates: ['2026-07-26', '2026-07-27', '2026-07-28', '2026-07-29', '2026-07-30'],
};

// A representative applicant overview (shape from a real over-views response).
function applicantRow() {
    return {
        applicationId: 'BGDRV0466B26', commissionId: SESSION.commissionId, commissionName: 'Rajshahi',
        dob: '20-OCT-1977', email: 'applicant@example.com', fullName: 'PROBE APPLICANT', ivacCenter: null,
        nidOrBr: '4660327166', passport: 'A14625632', phone: '01841424369', primary: true, visaType: 'FAMILY',
    };
}

// Return { status, json } for a faked URL, shaped to the site's REAL responses (shared by the
// operator) so each screen populates and the next step's request can fire. Order: specific first.
function synthFor(url) {
    const u = String(url).toLowerCase();

    // Auth
    if (/verifysigninotp|verify-otp|verify/.test(u) && /otp/.test(u)) {
        return envelope({ verified: true, verificationStatus: 'OTP verified', expiresAt: new Date(Date.now() + 300000).toISOString() });
    }
    if (/sign-?in/.test(u) && !/signup/.test(u)) {
        return envelope({ accessToken: fakeJwt(), tokenType: 'Bearer', expiresAt: 899, userId: '034a126e-bfc7-432d-9806-5daa0d9d033e', requestId: SESSION.requestId });
    }
    if (/signup/.test(u)) return envelope({ accessToken: fakeJwt(), tokenType: 'Bearer', requestId: SESSION.requestId, userId: '1' });

    // File / status — the stepper guards later pages on these flags, so they must reflect how far
    // the walk has progressed (PROGRESS is flipped by the walk after the upload step) or the app
    // bounces a jump-to-time-slot back to /appointment/notice.
    if (/file-confirmation|slot-status/.test(u)) {
        // fileUploadConfirmed/uploadEnd gate the mission form: while FALSE the app shows the
        // mission-selection form (→ high-commissions + booking-config fire); once the mission is
        // submitted (PROGRESS.missionSelected) they flip TRUE and time-slot opens.
        return envelope({
            fileUploadConfirmed: PROGRESS.missionSelected, num: 660, paymentConfirm: PROGRESS.paid,
            slotOpen: true, uploadEnd: PROGRESS.missionSelected, uploadFile: true,
        });
    }
    if (/upload_file|upload-file/.test(u)) {
        return envelope({ overview: applicantRow(), error: [] });
    }
    if (/over-?views?/.test(u)) return envelope([applicantRow()]);

    // Mission / center
    if (/high-commission/.test(u)) {
        return envelope([
            { id: 'ddfdbcb9-27dd-4abd-9e46-fcdb0d8c1895', missionName: 'Dhaka', city: 'Dhaka', code: 'HC_DHK_001' },
            { id: SESSION.commissionId, missionName: 'Rajshahi', city: 'Rajshahi', code: 'HC_RAJ_001' },
        ]);
    }
    if (/ivac-center/.test(u)) {
        return envelope([{ id: SESSION.centerId, centerName: 'IVAC, RAJSHAHI', addressLine1: 'Rajshahi', addressLine2: null, city: 'Rajshahi', postalCode: null, contactEmail: 'info@example.com', contactPhone: '000' }]);
    }

    // Booking config
    if (/appointment-booking-config/.test(u)) return envelope(null, 204);
    if (/get-booking-config/.test(u)) {
        // Until the walk submits the mission, report mission/center as NOT chosen so the app shows
        // the mission-selection form (and fires appointment-booking-config on submit) instead of
        // skipping straight to time-slot. PROGRESS.missionSelected flips after the submit.
        const sel = PROGRESS.missionSelected;
        return envelope({
            appointmentDate: sel ? SESSION.dates : [],
            appointmentId: SESSION.appointmentId,
            appointmentSlot: sel ? '09:00 AM - 10:00 AM' : null,
            fileUploadStatus: sel ? 'MISSION_CENTER_SELECTED' : 'FILE_UPLOADED',
            ivacCenter: sel ? 'IVAC, RAJSHAHI' : null,
            mission: sel ? 'Rajshahi' : null,
            numberOfApplicants: 1, totalAmount: 1500.0, visaCodes: null,
        });
    }

    // Reserve — NOTE: this endpoint returns a BARE object (no envelope).
    if (/reserve-?slot/.test(u)) {
        return { status: 200, json: { status: 'OK_NEW', reservationId: uuid(), appointmentDate: SESSION.dates[0], countByType: { FAMILY: 1 }, reserveTtlSeconds: 660, message: 'Reserved booking' } };
    }

    // Payment
    if (/payment-amount/.test(u)) return envelope(1500.0);
    if (/payment/.test(u) && /initiate/.test(u)) {
        return envelope({ webview_url: 'https://checkout.dgepay.net/payment/payment-methods?data=PROBE' }, 201);
    }

    // Appointment create + fallback
    if (/appointment/.test(u)) return envelope(null);
    return envelope(null);
}

// ─── Capture normalisation ───────────────────────────────────────────────────
// Headers the browser/transport manages itself — recorded for reference but flagged so a future
// executor knows not to replay them verbatim. Everything else (the x-sec-* / x-v-* / x-token
// family and the ciphered body) is the payload we actually want.
const TRANSPORT_HEADERS = new Set([
    'host', 'connection', 'content-length', 'accept', 'accept-encoding', 'accept-language',
    'user-agent', 'origin', 'referer', 'content-type', 'cookie', 'pragma', 'cache-control',
    'priority', 'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-ch-ua',
    'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'dnt', 'te',
]);

function normalizeCapture(rec) {
    const { baseUrl, path: reqPath } = splitUrl(rec.url);
    const appHeaders = {};
    const transportHeaders = {};
    for (const [k, v] of Object.entries(rec.headers || {})) {
        (TRANSPORT_HEADERS.has(k.toLowerCase()) ? transportHeaders : appHeaders)[k] = v;
    }
    let body = rec.body;
    let bodyType = 'raw';
    if (body && /^\s*[\[{]/.test(body)) {
        try { body = JSON.parse(body); bodyType = 'json'; } catch (e) { /* keep raw */ }
    } else if (rec.headers && /multipart\/form-data/i.test(rec.headers['content-type'] || '')) {
        bodyType = 'multipart';
    }
    return {
        step: rec.step || null,
        method: rec.method,
        url: rec.url,
        baseUrl,
        path: reqPath,
        appHeaders,
        transportHeaders,
        bodyType,
        body,
        capturedAt: new Date(rec.t).toISOString(),
    };
}

// ─── The probe ───────────────────────────────────────────────────────────────
/**
 * Run the offline bundle probe.
 *
 * @param {object} opts
 * @param {string} [opts.phone]     dummy phone typed into sign-in (structure only; can be junk)
 * @param {string} [opts.password]  dummy password
 * @param {string} [opts.otp]       dummy OTP typed into the verify screen
 * @param {string[]} [opts.filePaths] a PDF to attach on the upload screen (optional)
 * @param {number} [opts.graceMs=180000] time to keep capturing while you click around the window
 * @param {function} [opts.onLog]   (level, msg) progress callback
 * @param {string} [opts.outFile]   where to write the JSON dump (default ./probe-capture.json)
 * @returns {Promise<{ok, requests, byStep, outFile}>}
 */
async function probeBundle(opts = {}) {
    const log = (lvl, msg) => {
        try { (opts.onLog || (() => {}))(lvl, msg); } catch (e) { /* ignore */ }
        logger[lvl === 'error' ? 'error' : lvl === 'warn' ? 'warn' : 'info'](`[Probe] ${msg}`);
    };

    const phone = opts.phone || '01700000000';
    const password = opts.password || 'Probe@123';
    const otp = opts.otp || '123456';
    const filePaths = (opts.filePaths || []).filter(Boolean);
    const graceMs = opts.graceMs != null ? opts.graceMs : 180000;
    const outFile = opts.outFile || path.join(__dirname, 'probe-capture.json');
    const startUrl = opts.startUrl || (WEBSITE_URL.replace(/\/+$/, '') + '/signin');

    const captured = [];   // raw { step, method, url, headers, body, t }
    const seen = new Set(); // de-dupe identical (method+url+body) captures
    const diagnostics = []; // console errors + page errors, to explain why a screen didn't advance

    // A tiny valid PDF so the upload step has something to attach when the caller gives no file.
    if (!filePaths.length) {
        try {
            const p = path.join(os.tmpdir(), 'probe-dummy.pdf');
            fs.writeFileSync(p, MIN_PDF);
            filePaths.push(p);
        } catch (e) { /* upload step just won't fire */ }
    }

    const rb = await launchRecipeBrowser({ headless: false, log: (m) => log('info', m) });
    try {
        const page = rb.page;
        // Start every probe from a clean, first-time-visitor state (fresh profile + wiped
        // cookies/storage/cache), so a previous run's auth-storage can't make the SPA skip the
        // login page or replay a cached bundle.
        await rb.resetState();
        log('info', '🧼 Fresh session — cookies, storage and cache cleared.');

        // Turn the network OFF for the API and fake it. continue() everything else so the page
        // loads and Turnstile runs.
        await page.setRequestInterception(true);
        page.on('request', (req) => {
            let handled = false;
            try {
                const url = req.url();
                const method = req.method();
                const rt = req.resourceType();

                // CORS preflight for an API route → answer it so the real call proceeds.
                if (method === 'OPTIONS' && isApiRequest(url, 'xhr')) {
                    handled = true;
                    return req.respond({
                        status: 204,
                        headers: {
                            'access-control-allow-origin': '*',
                            'access-control-allow-methods': 'GET,POST,PUT,DELETE,OPTIONS',
                            'access-control-allow-headers': '*',
                        },
                    });
                }

                if (!isApiRequest(url, rt)) { handled = true; return req.continue(); }

                // Capture the fully-built request.
                const headers = req.headers() || {};
                const body = req.postData() || null;
                const step = matchStep(url, method);
                const key = `${method} ${url} ${body || ''}`;
                if (!seen.has(key)) {
                    seen.add(key);
                    captured.push({ step, method, url, headers, body, t: Date.now() });
                    const short = splitUrl(url).path.split('?')[0];
                    log('info', `📥 captured ${step || 'api'} — ${method} ${short}`);
                }

                // Return a synthetic success so the SPA advances (network stays off).
                handled = true;
                const { status, json } = synthFor(url);
                return req.respond({
                    status,
                    contentType: 'application/json',
                    headers: { 'access-control-allow-origin': '*' },
                    body: JSON.stringify(json),
                });
            } catch (e) {
                log('warn', `interceptor error: ${e.message}`);
                if (!handled) { try { req.continue(); } catch (e2) { /* already handled */ } }
            }
        });

        // Diagnostics: when a screen fails to advance it's almost always a synthetic response
        // missing a field the SPA reads — the console error names it. Collect those.
        page.on('console', (msg) => {
            try {
                const t = msg.type();
                if (t !== 'error' && t !== 'warning') return;
                const text = String(msg.text()).slice(0, 300);
                if (/turnstile|cloudflare|favicon|Download the React DevTools/i.test(text)) return;
                diagnostics.push({ kind: `console.${t}`, text });
                if (t === 'error') log('warn', `console.error: ${text.slice(0, 160)}`);
            } catch (e) { /* ignore */ }
        });
        page.on('pageerror', (err) => {
            const text = String((err && err.message) || err).slice(0, 300);
            diagnostics.push({ kind: 'pageerror', text });
            log('warn', `pageerror: ${text.slice(0, 160)}`);
        });

        const driver = new SiteDriver(page, log);
        const baseSite = WEBSITE_URL.replace(/\/+$/, '');

        // Poll for a field/predicate instead of a fixed sleep — the SPA re-renders on its own
        // clock, so the previous fixed sleeps were the reason only sign-in got captured.
        const waitForField = async (role, ms = 15000) => {
            const start = Date.now();
            while (Date.now() - start < ms) { if (await driver.hasField(role)) return true; await sleep(1000); }
            return false;
        };
        const ensureOnPage = async (p) => {
            try {
                const cur = new URL(page.url()).pathname.replace(/\/+$/, '');
                const tgt = new URL(baseSite + p).pathname.replace(/\/+$/, '');
                if (cur === tgt) return;
                log('info', `→ navigating to ${p}`);
                await page.goto(baseSite + p, { waitUntil: 'domcontentloaded', timeout: 60000 });
                await sleep(3000);
            } catch (e) { log('warn', `nav ${p} failed: ${e.message}`); }
        };
        // Real reload navigation (so zustand rehydrates the store we wrote), unconditional.
        const reloadTo = async (p) => {
            log('info', `→ ${p} (reload)`);
            try { await page.goto(baseSite + p, { waitUntil: 'domcontentloaded', timeout: 60000 }); await sleep(3000); }
            catch (e) { log('warn', `nav ${p} failed: ${e.message}`); }
        };

        // Load the sign-in page.
        log('info', `Opening ${startUrl} …`);
        await rb.goto(startUrl);
        await sleep(3500);

        // Confirm the bundle's cipher is reachable (proves the bundle really executed).
        try {
            await rb.installHook();
            const hasCipher = await rb.hasCipher().catch(() => false);
            log(hasCipher ? 'info' : 'warn', hasCipher ? 'Bundle cipher located — encryptText is callable.' : 'Cipher not found yet (capture still works).');
        } catch (e) { /* non-fatal */ }

        // ── Step 1: Sign in ────────────────────────────────────────────────────
        // Fill dummy creds. The captcha gates submit — inject a dummy token into the widget's
        // hidden input so the body carries a (dummy) `c`. The bundle ciphers it itself.
        await waitForField('phone', 12000);
        await driver.fillField('phone', phone);
        await driver.fillField('password', password);
        await injectDummyCaptcha(page);
        await sleep(600);
        await driver.clickButton(/sign ?in|log ?in|login|continue|submit|next/i);
        log('info', 'submitted sign-in — waiting for OTP screen…');

        // Between steps we can't rely on the SPA advancing on its own — each screen is guarded
        // and the real success envelope is obfuscated. Instead we write the SPA's OWN persisted
        // store (zustand under localStorage['auth-storage']) into the state the next guard wants,
        // reload into that screen (zustand rehydrates from what we wrote), and let it fire its
        // real request. The store shape is plaintext + stable; the volatile parts (url/headers/
        // cipher) are what we capture off the wire.
        const sessionToken = fakeJwt();
        const sessionReqId = uuid();

        // ── Step 2: Verify OTP ─────────────────────────────────────────────────
        await forceStore(page, { requestId: sessionReqId, phone, password, otpSentAt: Date.now(), token: sessionToken, isAuthenticated: true, isVerified: false });
        await reloadTo(opts.otpPath || '/verify-login-phone-otp');
        await sleep(1500);
        if (await typeOtp(page, driver, otp)) {
            await injectDummyCaptcha(page);
            await driver.clickButton(/verify|confirm|submit|continue|next/i);
            log('info', 'submitted OTP');
            await sleep(3000);
        } else {
            log('warn', 'OTP field not found even after forcing the store (see diagnostics).');
        }

        // The post-login flow lives under /appointment/*. Loading each page while authenticated
        // auto-fires that page's config/data calls (high-commissions, booking-config, over-views,
        // …) which we capture for free. The action POSTs (upload/reserve/payment) additionally
        // need a populated selection, attempted best-effort.
        // The post-login flow lives under /appointment/*. REAL ORDER (from live serverTimes):
        // upload → mission (select mission+center, which fires appointment-booking-config) →
        // time-slot → payment. We follow that order so every action POST fires; the mission guard
        // in particular needs upload to be done first.
        await forceStore(page, { token: sessionToken, isAuthenticated: true, isVerified: true });

        // ── Step 3: File upload (BEFORE mission) ────────────────────────────────
        // Entering the flow also fires createAppointment + over-views automatically → captured.
        await reloadTo(opts.uploadPath || '/appointment/file-upload');
        await sleep(2000);
        let fileInput = null;
        try { fileInput = await page.waitForSelector('input[type=file]', { timeout: 9000 }); } catch (e) { /* none */ }
        if (fileInput) {
            // The upload POST (upload_file_v23) auto-fires on the input's change event — no submit
            // button. Let the applicant row (from over-views) finish wiring up first, or onChange
            // won't trigger the upload.
            await sleep(2500);
            await driver.attachFiles(filePaths);
            await sleep(3500);
        } else {
            log('warn', 'no file input on the upload page (still captured any auto-fired calls).');
        }
        PROGRESS.uploaded = true; // unlocks the mission + time-slot guards

        // ── Step 3b: Mission + IVAC-center selection → fires appointment-booking-config ─────────
        await reloadTo(opts.missionPath || '/appointment/mission');
        await sleep(3500);
        await driveMissionPage(page, driver, log); // pick mission → pick center → submit (fires booking-config)
        PROGRESS.missionSelected = true; // now time-slot/reserve is unlocked
        await sleep(2000);

        // ── Step 4: Reserve slot ────────────────────────────────────────────────
        // time-slot shows "Pick up a date" → a list of dates → "Continue Booking", which fires
        // the reserve POST and navigates to /appointment/continue-payment.
        await reloadTo(opts.reservePath || '/appointment/time-slot');
        await sleep(3500);
        await driver.clickButton(/pick ?up a date|pick.*date|select.*date|choose.*date/i);
        await sleep(1500);
        await pickFirstDate(page);
        await sleep(800);
        await injectDummyCaptcha(page);
        await driver.clickButton(/continue ?booking|reserve|book|proceed|confirm/i);
        await sleep(3500);
        PROGRESS.reserved = true;

        // ── Step 5: Payment initiate ────────────────────────────────────────────
        // On /appointment/continue-payment: select the DGePay gateway, then "Continue Payment"
        // fires v1/payment/<serviceId>/dg-epay/initiate.
        await sleep(1500);
        await driver.clickButton(/pay with|dg-?epay/i);
        await sleep(1500);
        await injectDummyCaptcha(page);
        await driver.clickButton(/continue payment|proceed|confirm|initiate/i);
        await sleep(3500);
        PROGRESS.paid = true;

        // ── Grace period: finish anything by hand ───────────────────────────────
        // Every click that fires an API call is captured + faked, so you can complete any
        // step the auto-walk missed, in the window, with no live slot.
        const need = ['signin', 'verifyOtp', 'upload', 'bookingConfig', 'reserve', 'payment'].filter((s) => !captured.some((c) => c.step === s));
        if (need.length) log('warn', `👉 Still missing: ${need.join(', ')}. Finish those in the window — capturing for ${Math.round(graceMs / 1000)}s.`);
        else log('info', `All five steps captured. Grace window open ${Math.round(graceMs / 1000)}s for anything extra.`);
        const start = Date.now();
        while (Date.now() - start < graceMs) await sleep(2000);

        // ── Dump ───────────────────────────────────────────────────────────────
        const requests = captured.map(normalizeCapture);
        const byStep = {};
        for (const r of requests) {
            const k = r.step || 'other';
            (byStep[k] = byStep[k] || []).push(r);
        }
        // The role values the walk fed in, so the mapper can tag which captured fields are dynamic
        // (filled per-account at runtime) vs static (replayed verbatim). Auto mode knows them all.
        const known = {
            phone, password, otpCode: otp,
            bearer: typeof sessionToken !== 'undefined' ? sessionToken : null,
            requestId: typeof sessionReqId !== 'undefined' ? sessionReqId : null,
            appointmentId: SESSION.appointmentId,
            appointmentDate: SESSION.dates[0],
            mission: 'Rajshahi', ivacCenter: 'IVAC, RAJSHAHI', // the synthetic mission/center the walk uses
            missionId: SESSION.commissionId, // for templatizing ivac-centers/<missionId> in the path
        };
        const out = { probedAt: new Date().toISOString(), website: WEBSITE_URL, count: requests.length, byStep, requests, diagnostics: diagnostics.slice(0, 40), known };
        fs.writeFileSync(outFile, JSON.stringify(out, null, 2));
        log('info', `✅ Probe complete. Captured ${requests.length} request(s): ${Object.keys(byStep).map((k) => `${k}×${byStep[k].length}`).join(', ') || 'none'}.`);
        log('info', `📄 Wrote ${outFile}`);

        return { ok: requests.length > 0, requests, byStep, outFile };
    } finally {
        await rb.close();
    }
}

/**
 * Attended capture: open the browser to the LIVE site (real network, nothing faked) and let the
 * OPERATOR drive the flow — sign in, solve the captcha, do OTP, upload, reserve, pay. Every API
 * request is recorded passively as it goes out, written to `outFile` after each capture (so the
 * data survives even if the run is killed). Finalizes when the operator CLOSES the browser window.
 *
 * This is the most accurate capture — the real server responses drive the SPA, so there's no
 * synthetic-response or store-forcing guesswork. The only limit is that slot-gated steps
 * (reserve/payment) still need a real slot to click, just like the live site.
 *
 * @param {object} opts
 * @param {string} [opts.startUrl]  where to open (default the /signin page)
 * @param {string} [opts.outFile]   JSON dump path (default ./probe-capture.json)
 * @param {number} [opts.maxMs]     safety cap before auto-finalizing (default 30 min)
 * @param {function} [opts.onLog]   (level, msg) progress callback
 */
async function probeAttended(opts = {}) {
    const log = (lvl, msg) => {
        try { (opts.onLog || (() => {}))(lvl, msg); } catch (e) { /* ignore */ }
        logger[lvl === 'error' ? 'error' : lvl === 'warn' ? 'warn' : 'info'](`[Probe] ${msg}`);
    };
    const outFile = opts.outFile || path.join(__dirname, 'probe-capture.json');
    const startUrl = opts.startUrl || (WEBSITE_URL.replace(/\/+$/, '') + '/signin');
    const maxMs = opts.maxMs || 30 * 60 * 1000;

    const captured = [];
    const seen = new Set();

    const writeOut = () => {
        try {
            const requests = captured.map(normalizeCapture);
            const byStep = {};
            for (const r of requests) { const k = r.step || 'other'; (byStep[k] = byStep[k] || []).push(r); }
            fs.writeFileSync(outFile, JSON.stringify({ probedAt: new Date().toISOString(), mode: 'attended', website: WEBSITE_URL, count: requests.length, byStep, requests }, null, 2));
        } catch (e) { log('warn', `write failed: ${e.message}`); }
    };

    // Passive recorder — no interception, so the real site works normally (real login/captcha/OTP).
    const record = (req) => {
        try {
            const url = req.url();
            const method = req.method();
            if (!isApiRequest(url, req.resourceType())) return;
            const body = req.postData() || null;
            const key = `${method} ${url} ${body || ''}`;
            if (seen.has(key)) return;
            seen.add(key);
            const step = matchStep(url, method);
            captured.push({ step, method, url, headers: req.headers() || {}, body, t: Date.now() });
            log('info', `📥 ${step || 'api'} — ${method} ${splitUrl(url).path.split('?')[0]}  (total ${captured.length})`);
            writeOut();
        } catch (e) { /* never let a capture handler throw */ }
    };

    const rb = await launchRecipeBrowser({ headless: false, log: (m) => log('info', m) });
    // Same first-time-visitor guarantee for the attended run — you always start at a real login.
    await rb.resetState();
    log('info', '🧼 Fresh session — cookies, storage and cache cleared.');
    rb.page.on('request', record);
    // Payment can open the gateway in a new tab/popup — record there too.
    rb.browser.on('targetcreated', async (target) => {
        try { const p = await target.page(); if (p) p.on('request', record); } catch (e) { /* ignore */ }
    });

    await rb.goto(startUrl);
    log('warn', '👉 Operate the flow in the browser window — sign in, solve the captcha, OTP, upload, reserve, pay. I capture every request live. CLOSE THE BROWSER WINDOW when you are done and I finalize the file.');

    // Wait until the operator closes the browser (disconnected) or the safety cap elapses.
    await new Promise((resolve) => {
        let done = false;
        const finish = () => { if (done) return; done = true; resolve(); };
        rb.browser.on('disconnected', finish);
        setTimeout(finish, maxMs);
    });

    writeOut();
    const byStep = {};
    for (const r of captured) { const k = r.step || 'other'; byStep[k] = (byStep[k] || 0) + 1; }
    log('info', `✅ Attended capture finished. ${captured.length} request(s): ${Object.entries(byStep).map(([k, n]) => `${k}×${n}`).join(', ') || 'none'}.`);
    log('info', `📄 Wrote ${outFile}`);
    try { await rb.close(); } catch (e) { /* already gone */ }
    return { ok: captured.length > 0, count: captured.length, outFile };
}

// Write the SPA's own persisted auth store (zustand → localStorage['auth-storage']) so the next
// screen's route guard is satisfied without decoding the site's obfuscated success envelope. The
// store shape is plaintext and part of the stable "steps always exist" skeleton; a reload after
// this rehydrates the store from what we wrote. `patch` overrides individual fields.
const AUTH_STORE_KEY = 'auth-storage';
async function forceStore(page, patch) {
    try {
        await page.evaluate((key, patch) => {
            let cur = {};
            try { cur = JSON.parse(localStorage.getItem(key) || '{}'); } catch (e) { /* fresh */ }
            const base = {
                token: null, userId: null, expiresAt: null, isAuthenticated: false, isVerified: false,
                requestId: null, phone: null, password: null, otpSentAt: null, hasHydrated: true,
            };
            const state = Object.assign(base, (cur && cur.state) || {}, patch);
            localStorage.setItem(key, JSON.stringify({ state, version: (cur && cur.version) || 0 }));
        }, AUTH_STORE_KEY, patch);
    } catch (e) { /* store may not exist yet — non-fatal */ }
}

// Enter an OTP into either a multi-box widget (one char per input, auto-advancing) or a single
// field. Clicks the first OTP-ish input and types with the keyboard so auto-advance distributes
// the digits; falls back to the scorer-based fill. Returns true if it found somewhere to type.
async function typeOtp(page, driver, code) {
    try {
        const handle = await page.evaluateHandle(() => {
            const cand = [...document.querySelectorAll(
                'input[autocomplete="one-time-code"], input[inputmode="numeric"], input[maxlength="1"], input[type="tel"], input[type="number"], input[type="text"]'
            )].filter((el) => {
                const r = el.getBoundingClientRect();
                return r.width > 0 && r.height > 0 && !el.disabled && !el.readOnly;
            });
            return cand[0] || null;
        });
        const el = handle.asElement();
        if (el) {
            await el.click();
            await page.keyboard.type(String(code), { delay: 60 });
            return true;
        }
    } catch (e) { /* fall through */ }
    return await driver.fillField('otp', code);
}

// Click the first date-looking option in the time-slot date picker (dates render as DD-MM-YYYY /
// YYYY-MM-DD list items, not a native <select>). Returns true if it clicked one.
async function pickFirstDate(page) {
    try {
        return await page.evaluate(() => {
            const vis = (el) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0; };
            const cand = [...document.querySelectorAll('[role=option],li,button,td,[class*=day],[class*=Day],[class*=date],[class*=Date],[class*=option],[class*=Option]')]
                .filter(vis)
                .find((e) => /\d{2}-\d{2}-\d{4}|\d{4}-\d{2}-\d{2}/.test((e.innerText || '').trim()) && !/pick|continue|profile|logout/i.test(e.innerText || ''));
            if (cand) { cand.click(); return true; }
            return false;
        });
    } catch (e) { return false; }
}

// Drive the mission page: advance past any notice, pick a mission, pick an IVAC center, submit.
// Selecting the mission triggers the ivac-centers fetch; submitting fires appointment-booking-config.
// Handles native <select> AND custom (react-select/combobox) dropdowns.
async function driveMissionPage(page, driver, log) {
    await sleep(1000);
    // The mission + IVAC-center pickers are BUTTONS ("Select a mission" / "Select your IVAC
    // center") that open a menu; a submit button "Confirm Mission & IVAC Center" fires
    // appointment-booking-config.
    await driver.clickButton(/select a mission|select mission|choose.*mission/i);
    await sleep(1500);
    await clickFirstMenuOption(page, log, 'mission');
    await sleep(2800); // picking the mission triggers the ivac-centers fetch + re-render

    // NB: must require "select"/"choose" — a bare "ivac center" also matches the "Confirm Mission
    // & IVAC Center" submit button, which the scorer would prefer, submitting with no center.
    await driver.clickButton(/select your ivac|select.*center|choose.*center/i);
    await sleep(2200); // let the center menu render before picking
    await clickFirstMenuOption(page, log, 'center');
    await sleep(1500);

    await driver.clickButton(/confirm mission|confirm.*ivac|confirm & |confirm and |confirm|submit|proceed/i);
    await sleep(3000);
}

// Click the first real option in an open menu/listbox (excludes the trigger/nav buttons).
async function clickFirstMenuOption(page, log, what) {
    const picked = await page.evaluate(() => {
        const vis = (el) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0; };
        // Option rows are single-line <button>s with a real name (e.g. "Dhaka", "IVAC, RAJSHAHI").
        // Exclude the trigger/submit/nav buttons, the info "i" icon, and multi-line containers.
        const opts = [...document.querySelectorAll('button,[role=option],[role=menuitem],li')]
            .filter(vis)
            .filter((e) => {
                const t = (e.innerText || '').trim();
                if (!t || t.length > 40 || t.includes('\n')) return false;
                if (/^i$/i.test(t)) return false;
                if (/select|choose|confirm|logout|profile|please|pick|continue|next|proceed|submit|back|cancel/i.test(t)) return false;
                return true;
            });
        if (opts[0]) { opts[0].click(); return (opts[0].innerText || '').trim().slice(0, 30); }
        return null;
    }).catch(() => null);
    log('info', `mission page: picked ${what} = ${picked || '(none found)'}`);
    return picked;
}

// Best-effort: set every native <select> to its first non-empty option and fire change (React
// controlled selects need the native setter + input/change). Helps the cascading mission /
// slot pickers populate downstream state so the action POST can fire. Harmless if there are none.
async function selectFirstOptions(page) {
    try {
        await page.evaluate(() => {
            document.querySelectorAll('select').forEach((sel) => {
                const opt = [...sel.options].find((o) => o.value && !/^\s*$/.test(o.value));
                if (!opt) return;
                const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set;
                setter.call(sel, opt.value);
                sel.dispatchEvent(new Event('input', { bubbles: true }));
                sel.dispatchEvent(new Event('change', { bubbles: true }));
            });
        });
    } catch (e) { /* ignore */ }
}

// Put a dummy token in the Turnstile hidden input and dispatch input/change so a form that reads
// the hidden field (rather than the widget callback) lets submit through. Best-effort.
async function injectDummyCaptcha(page) {
    try {
        await page.evaluate(() => {
            const dummy = '0.probe-dummy-token.' + Math.random().toString(36).slice(2);
            const inputs = document.querySelectorAll('[name="cf-turnstile-response"], [name="g-recaptcha-response"], [name="h-captcha-response"]');
            inputs.forEach((el) => {
                const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
                setter.call(el, dummy);
                el.dispatchEvent(new Event('input', { bubbles: true }));
                el.dispatchEvent(new Event('change', { bubbles: true }));
            });
        });
    } catch (e) { /* ignore — operator can solve it in the window */ }
}

module.exports = { probeBundle, probeAttended, _internals: { synthFor, isApiRequest, normalizeCapture, API_PATH_RE, PROGRESS } };

// Allow `node bundleProbe.js` for a quick manual run.
if (require.main === module) {
    probeBundle({ onLog: (lvl, m) => console.log(`[${lvl}] ${m}`) })
        .then((r) => { console.log('done:', r.ok, r.outFile); process.exit(0); })
        .catch((e) => { console.error('probe failed:', e); process.exit(1); });
}
