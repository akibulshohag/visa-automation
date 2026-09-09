/**
 * probeMapper.js — merges a bundleProbe capture (probe-capture.json) into the live config the
 * bot actually runs on, so a probe run auto-adjusts api.js to whatever the site changed this week.
 *
 * bundleProbe.js captures each step's real request (URL, headers, body) off the running bundle.
 * This maps those captures onto the `ep_*` config keys api.js reads (base URL, rotating path,
 * the x-sec- / x-v- header values, the reserve slotId + payment serviceId). It is PER-STEP and
 * PARTIAL-SAFE: only steps present in the capture are updated, so an attended run that only got
 * as far as sign-in updates sign-in and leaves the rest untouched.
 *
 * Cipher KEYS are NOT touched here — those come from cipherKeys.js. This only moves the
 * endpoint/header surface the probe learns.
 */

const fs = require('fs');
const path = require('path');
const { getConfig, setConfig, logger } = require('./database');

const DEFAULT_CAPTURE = path.join(__dirname, 'probe-capture.json');

// Trailing-slash-normalise a base URL so `${base}${endpoint}` joins cleanly.
function normBase(u) {
    if (!u) return null;
    return u.endsWith('/') ? u : u + '/';
}
function stripQuery(p) {
    return String(p || '').split('?')[0].replace(/^\/+/, '');
}
function hdr(req, name) {
    const h = req.appHeaders || {};
    for (const k of Object.keys(h)) { if (k.toLowerCase() === name) return h[k]; }
    return null;
}

// Find the capture for a step, or (for the config-GET steps that land under `other`) by a path
// fragment. Returns the request object or null.
function pick(capture, { step, pathIncludes }) {
    const reqs = capture.requests || [];
    if (step) { const r = reqs.find((x) => x.step === step); if (r) return r; }
    if (pathIncludes) { return reqs.find((x) => new RegExp(pathIncludes, 'i').test(x.path || '')) || null; }
    return null;
}

/**
 * Derive the { configKey: value } updates from a capture. Only keys whose source request is
 * present (and whose value is non-empty) are included.
 */
function deriveConfig(capture) {
    const out = {};
    const put = (k, v) => { if (v != null && String(v).length) out[k] = String(v); };

    // sign-in
    const signin = pick(capture, { step: 'signin' });
    if (signin) {
        put('ep_signin_url', normBase(signin.baseUrl));
        put('ep_signin_path', stripQuery(signin.path));
        put('ep_signin_nav_state', hdr(signin, 'x-sec-navigation-state'));
    }

    // verify OTP
    const otp = pick(capture, { step: 'verifyOtp' });
    if (otp) {
        put('ep_verifyotp_url', normBase(otp.baseUrl));
        put('ep_verifyotp_path', stripQuery(otp.path));
    }

    // file upload + its sibling over-views (base URL for the whole file-upload phase)
    const upload = pick(capture, { step: 'upload' });
    if (upload) {
        put('ep_fileupload_url', normBase(upload.baseUrl));
        put('ep_upload_path', stripQuery(upload.path));
        put('ep_upload_runtime_state', hdr(upload, 'x-sec-runtime-state'));
    }
    const overviews = pick(capture, { pathIncludes: 'over-?views?' });
    if (overviews) put('ep_overviews_path', stripQuery(overviews.path));

    // reserve — base, request-meta header, and the slotId embedded in the path
    const reserve = pick(capture, { step: 'reserve' });
    if (reserve) {
        put('ep_reserve_url', normBase(reserve.baseUrl));
        put('ep_reserve_request_meta', hdr(reserve, 'x-v-request-meta'));
        const m = String(reserve.path || '').match(/\/?slots\/([^/]+)\/reserve/i);
        if (m) put('ep_reserve_slot_id', m[1]);
    }

    // payment — base + the serviceId embedded in the path
    const payment = pick(capture, { step: 'payment' });
    if (payment) {
        put('ep_payment_url', normBase(payment.baseUrl));
        const m = String(payment.path || '').match(/\/?payment\/([^/]+)\/dg-?epay/i);
        if (m) put('ep_payment_service_id', m[1]);
    }

    return out;
}

// ─── Full recipe (for the generic executor) ──────────────────────────────────
// Beyond the scalar ep_* keys, we build a per-step RECIPE so api.js can replay each request
// verbatim — every header name+value and body field — substituting only the runtime dynamics.
// This is what makes ANY change (a renamed header, a new header, a reshaped path/body) auto-adjust.

// Is this value the ciphered captcha (the site's "1.<blob>" form or a long high-entropy token)?
function looksCiphered(v) {
    const s = String(v == null ? '' : v);
    return (/^\d+\.[A-Za-z0-9._-]{20,}/.test(s)) || (s.length >= 60 && /[A-Za-z]/.test(s) && /[0-9]/.test(s) && !/\s/.test(s));
}

// Decide the role of one body/header value. Uses known role-values (auto mode knows them all);
// falls back to the field NAME when the value can't be matched (e.g. attended captures).
function roleOf(key, value, known) {
    const s = value == null ? '' : String(value);
    const name = String(key || '').toLowerCase();
    // exact value matches against what the walk fed in
    if (known) {
        if (known.phone && s === known.phone) return 'phone';
        if (known.password && s === known.password) return 'password';
        if (known.otpCode && s === known.otpCode) return 'otpCode';
        if (known.requestId && s === known.requestId) return 'requestId';
        if (known.appointmentId && s === known.appointmentId) return 'appointmentId';
        if (known.appointmentDate && s === known.appointmentDate) return 'appointmentDate';
        if (known.mission && s === known.mission) return 'mission';
        if (known.ivacCenter && s === known.ivacCenter) return 'ivacCenter';
        if (known.bearer && (s === known.bearer || s === 'Bearer ' + known.bearer)) return 'bearer';
    }
    // the captcha field (ciphered) — by key name `c` or by shape
    if (name === 'c' || name === 'captcha' || looksCiphered(s)) return 'captcha';
    // name-based fallback (attended: values unknown)
    if (name === 'phone' || name === 'mobile') return 'phone';
    if (name === 'password') return 'password';
    if (name === 'code' || name === 'otp') return 'otpCode';
    if (name === 'requestid') return 'requestId';
    if (name === 'appointmentid') return 'appointmentId';
    if (name === 'appointmentdate' || name === 'date') return 'appointmentDate';
    if (name === 'mission') return 'mission';
    if (name === 'ivaccenter' || name === 'center' || name === 'centername') return 'ivacCenter';
    return null; // → constant, replayed verbatim
}

// Canonical recipe key for any api.js endpoint, derived from its PATH (+ method). Keeps the
// recipe keyed the same way api.js looks it up, and works on old captures (doesn't rely on the
// capture's `step` label). Order matters — most specific first.
function stepKeyForPath(path, method) {
    const p = String(path || '').toLowerCase();
    const m = String(method || '').toUpperCase();
    if (/auth\/[^/]*sign-?in/.test(p)) return 'signin';
    if (/otp\/verifysigninotp/.test(p)) return 'verifyOtp';
    if (/otp\/signupotp/.test(p)) return 'signupOtp';
    if (/otp\/verifyotp/.test(p)) return 'signupVerify';
    if (/auth\/signup/.test(p)) return 'signup';
    if (/slots\/[^/]+\/reserve/.test(p)) return 'reserve';
    if (/payment\/[^/]+\/dg-?epay\/initiate/.test(p)) return 'payment';
    if (/file\/upload[_-]file/.test(p)) return 'upload';
    if (/file\/over-?views?/.test(p)) return 'overviews';
    if (/file\/file-confirmation/.test(p)) return 'fileConfirmation';
    if (/appointment\/appointment-booking-config/.test(p)) return 'bookingConfig';
    if (/appointment\/get-booking-config/.test(p)) return 'getBookingConfig';
    if (/high-commissions?/.test(p)) return 'highCommissions';
    if (/ivac-centers?/.test(p)) return 'ivacCenters';
    if (/invoice\/all-by-user/.test(p)) return 'invoices';
    if (/invoice\/download/.test(p)) return 'invoiceDownload';
    if (/(^|\/)appointment$/.test(p) && m === 'POST') return 'createAppointment';
    return null;
}

function buildStepRecipe(req, known) {
    const headers = [];
    for (const [name, value] of Object.entries(req.appHeaders || {})) {
        const lname = name.toLowerCase();
        if (lname === 'authorization') { headers.push({ name, role: 'bearer' }); continue; }
        if (lname === 'x-token') { headers.push({ name, role: 'tokenHeader' }); continue; }
        if (/device/i.test(name)) { headers.push({ name, role: 'deviceId' }); continue; }
        headers.push({ name, value: String(value) }); // static app header (x-sec-*, x-v-*), replay verbatim
    }
    let body = { type: req.bodyType, entries: [] };
    if (req.bodyType === 'json' && req.body && typeof req.body === 'object' && !Array.isArray(req.body)) {
        for (const [key, value] of Object.entries(req.body)) {
            const role = roleOf(key, value, known);
            body.entries.push(role ? { key, role } : { key, value });
        }
    } else if (req.bodyType === 'multipart') {
        // Multipart field bytes aren't captured; the file itself is the only dynamic — the caller
        // (uploadFile) supplies the form fields. Recipe still carries url + headers for upload.
        body = { type: 'multipart', entries: [{ key: 'files', role: 'file' }] };
    }
    // Templatize dynamic PATH params we know (e.g. ivac-centers/<missionId>) into {role}
    // placeholders the executor fills at runtime. Static ids in the path (reserve slotId, payment
    // serviceId) are NOT in `known`, so they stay literal and are refreshed each probe.
    let recipePath = stripQuery(req.path);
    if (known && known.missionId) recipePath = recipePath.split(known.missionId).join('{missionId}');
    // Pattern-based fallback for the parameterized GET, robust to WHICH mission was captured:
    // v1/ivac-centers/<anything> → v1/ivac-centers/{missionId}. (?!\{) avoids double-templating.
    recipePath = recipePath.replace(/(ivac-centers?\/)(?!\{)[^/?]+/i, '$1{missionId}');
    return { method: req.method, baseUrl: normBase(req.baseUrl), path: recipePath, headers, body };
}

// Build recipe steps for EVERY api.js endpoint present in the capture (keyed canonically).
function buildRecipe(capture) {
    const known = capture.known || null;
    const steps = {};
    for (const req of capture.requests || []) {
        const step = stepKeyForPath(req.path, req.method);
        if (!step) continue;
        steps[step] = buildStepRecipe(req, known);
    }
    return steps;
}

/**
 * Apply a capture to config. Writes only the derived keys whose value actually changed.
 * @param {object|string} [captureOrPath] capture object, a path, or undefined (default file)
 * @param {function} [log] (msg) progress callback
 * @returns {Promise<{updated:object, unchanged:string[], source:string}>}
 */
async function applyCapture(captureOrPath, log = () => {}) {
    let capture = captureOrPath;
    let source = 'object';
    if (!capture || typeof capture === 'string') {
        source = capture || DEFAULT_CAPTURE;
        capture = JSON.parse(fs.readFileSync(source, 'utf8'));
    }

    const derived = deriveConfig(capture);
    const keys = Object.keys(derived);
    if (!keys.length) {
        log('No mappable steps in the capture — nothing to apply.');
        return { updated: {}, unchanged: [], source };
    }

    const config = await getConfig();
    const updated = {};
    const unchanged = [];
    for (const k of keys) {
        const nv = derived[k];
        if (String(config[k] ?? '') === nv) { unchanged.push(k); continue; }
        await setConfig(k, nv);
        updated[k] = nv;
        log(`✎ ${k} = ${nv.length > 60 ? nv.slice(0, 57) + '…' : nv}`);
    }

    // Build + merge the full per-step recipe (partial-safe: only steps present in this capture are
    // replaced; steps from a previous fuller capture are kept). This drives api.js's generic
    // executor so ANY header/body/path change is followed, not just the mapped scalars.
    const newSteps = buildRecipe(capture);
    if (Object.keys(newSteps).length) {
        let recipe = { version: 1, steps: {} };
        try { if (config.probe_recipe_json) recipe = JSON.parse(config.probe_recipe_json); } catch (e) { /* rebuild */ }
        recipe.steps = Object.assign(recipe.steps || {}, newSteps);
        recipe.learnedAt = new Date().toISOString();
        await setConfig('probe_recipe_json', JSON.stringify(recipe));
        updated.probe_recipe_json = `steps: ${Object.keys(newSteps).join(', ')}`;
        log(`✎ recipe steps updated: ${Object.keys(newSteps).join(', ')}`);
    }

    await setConfig('probe_applied_at', new Date().toISOString());

    const changedCount = Object.keys(updated).length;
    log(changedCount ? `✅ Applied ${changedCount} change(s); ${unchanged.length} already current.`
        : `✅ Config already matches the capture (${unchanged.length} keys checked).`);
    logger.info(`[ProbeMapper] applied ${changedCount} change(s) from ${source}`);
    return { updated, unchanged, source };
}

module.exports = { applyCapture, deriveConfig, buildRecipe, _internals: { normBase, stripQuery, pick, roleOf, buildStepRecipe, stepKeyForPath } };
