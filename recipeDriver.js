/**
 * recipeDriver.js — resilient auto-driver for the Recipe Learner walk.
 *
 * The site's DOM (ids, classes, field names) rotates every week just like its request
 * shapes, so we never hardcode selectors. Instead we SCORE candidate elements in-page by
 * what they intrinsically are — input type, maxlength, placeholder/aria-label/name text,
 * nearby label text, button caption — mark the winner with a data attribute, and act on it
 * from Node with real mouse/keyboard events (React only reacts to genuine events).
 *
 * Nothing here hard-fails the run: if an element can't be found, the caller logs "do this
 * step in the window" and keeps capturing, so a partly-automated walk still yields a recipe.
 */

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const MARK = 'data-recipe-target';

// ─── In-page scorers (serialized into the browser) ───────────────────────────
// Returns true if it marked an element, false if nothing plausible was found.
function __markField(role, markAttr) {
    const vis = (el) => {
        const r = el.getBoundingClientRect();
        const s = getComputedStyle(el);
        return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && !el.disabled && !el.readOnly;
    };
    const textFor = (el) => {
        let t = [el.getAttribute('name'), el.getAttribute('id'), el.getAttribute('placeholder'),
                 el.getAttribute('aria-label'), el.getAttribute('autocomplete'), el.getAttribute('inputmode')]
                 .filter(Boolean).join(' ');
        // include an associated / ancestor label's text
        try {
            if (el.id) { const l = document.querySelector(`label[for="${CSS.escape(el.id)}"]`); if (l) t += ' ' + l.innerText; }
            const wrap = el.closest('label, .form-group, .field, div');
            if (wrap && wrap.innerText && wrap.innerText.length < 120) t += ' ' + wrap.innerText;
        } catch (e) { /* ignore */ }
        return t.toLowerCase();
    };

    const all = [...document.querySelectorAll('input, textarea')].filter(vis);
    let best = null, bestScore = 0;
    for (const el of all) {
        const type = (el.getAttribute('type') || 'text').toLowerCase();
        const t = textFor(el);
        const ml = parseInt(el.getAttribute('maxlength') || '0', 10);
        let score = 0;

        if (role === 'password') {
            if (type === 'password') score += 100;
            if (/pass/.test(t)) score += 30;
        } else if (role === 'phone') {
            if (type === 'tel') score += 60;
            if (/phone|mobile|mobil|number|msisdn/.test(t)) score += 50;
            if (type === 'password') score -= 100;
            if (/pass|otp|code|email/.test(t)) score -= 40;
        } else if (role === 'otp') {
            if (/otp|code|verif|pin/.test(t)) score += 60;
            if (ml > 0 && ml <= 8) score += 40;
            if (type === 'tel' || type === 'number' || type === 'text') score += 10;
            if (type === 'password') score -= 60;
            if (/pass|phone|mobile|email/.test(t)) score -= 50;
        } else if (role === 'email') {
            if (type === 'email') score += 100;
            if (/email|mail/.test(t)) score += 30;
        }
        if (score > bestScore) { bestScore = score; best = el; }
    }
    document.querySelectorAll('[' + markAttr + ']').forEach((e) => e.removeAttribute(markAttr));
    if (best && bestScore >= 40) { best.setAttribute(markAttr, '1'); return true; }
    return false;
}

// Mark a clickable whose caption matches `pattern` (a source string for a RegExp).
function __markClickable(pattern, markAttr) {
    const re = new RegExp(pattern, 'i');
    const vis = (el) => {
        const r = el.getBoundingClientRect();
        const s = getComputedStyle(el);
        return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && !el.disabled;
    };
    const cands = [...document.querySelectorAll('button, input[type=submit], input[type=button], a, [role=button]')].filter(vis);
    let best = null, bestScore = 0;
    for (const el of cands) {
        const label = ((el.innerText || '') + ' ' + (el.value || '') + ' ' + (el.getAttribute('aria-label') || '')).trim();
        if (!re.test(label)) continue;
        let score = 10 + Math.max(0, 40 - label.length);           // prefer a tight, exact caption
        if (el.tagName === 'BUTTON' || el.type === 'submit') score += 20;
        if (score > bestScore) { bestScore = score; best = el; }
    }
    document.querySelectorAll('[' + markAttr + ']').forEach((e) => e.removeAttribute(markAttr));
    if (best) { best.setAttribute(markAttr, '1'); return true; }
    return false;
}

// Mark the first usable file input (they are often visually hidden, so skip the vis check).
function __markFileInput(markAttr) {
    const el = document.querySelector('input[type=file]');
    document.querySelectorAll('[' + markAttr + ']').forEach((e) => e.removeAttribute(markAttr));
    if (el) { el.setAttribute(markAttr, '1'); return true; }
    return false;
}

// Collect visible on-screen error text so we can report WHY a step failed.
function __readErrors() {
    const out = [];
    // Deliberately broad: obfuscated builds shorten these to things like `_err`, so match the
    // stem rather than the whole word, in both cases. False positives are harmless — this text
    // is only logged to explain why a step failed.
    const sel = [
        '[class*=err]', '[class*=Err]', '[class*=invalid]', '[class*=Invalid]',
        '[role=alert]', '[class*=alert]', '[class*=Alert]',
        '[class*=toast]', '[class*=Toast]', '[class*=danger]', '[class*=Danger]',
        '[aria-invalid=true]',
    ].join(', ');
    document.querySelectorAll(sel).forEach((e) => {
        const t = (e.innerText || '').trim();
        if (t && t.length < 200) out.push(t);
    });
    return [...new Set(out)].slice(0, 5);
}

class SiteDriver {
    constructor(page, log) {
        this.page = page;
        this.log = log || (() => {});
    }

    async _marked() { return await this.page.$(`[${MARK}]`); }

    // Type `value` into the field that best matches `role`. Real click + keystrokes so React
    // state updates. Returns false when no plausible field is on screen.
    async fillField(role, value) {
        const found = await this.page.evaluate(__markField, role, MARK);
        if (!found) return false;
        const el = await this._marked();
        if (!el) return false;
        const want = String(value);
        try {
            try {
                await el.click({ clickCount: 3 });             // select any existing text
                await this.page.keyboard.press('Backspace');
                await el.type(want, { delay: 60 });
            } catch (e) { /* focus may have been stolen — the fallback below handles it */ }

            // Verify what actually landed. A captcha widget (or any overlay) can steal focus
            // mid-typing and swallow the keystrokes, so fall back to setting the value through
            // the native setter and firing input/change — the React-safe way to update a
            // controlled input without needing focus at all.
            let got = await el.evaluate((e) => e.value).catch(() => null);
            if (got !== want) {
                await el.evaluate((e, v) => {
                    const proto = (e instanceof HTMLTextAreaElement) ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
                    const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
                    setter.call(e, v);
                    e.dispatchEvent(new Event('input', { bubbles: true }));
                    e.dispatchEvent(new Event('change', { bubbles: true }));
                }, want);
                got = await el.evaluate((e) => e.value).catch(() => null);
                if (got === want) this.log('info', `↳ ${role}: typing was blocked (focus stolen) — set the value directly instead.`);
            }
            if (got !== want) { this.log('warn', `Could not set ${role} (field holds "${got}")`); return false; }
            return true;
        } catch (e) {
            this.log('warn', `Could not type into ${role}: ${e.message}`);
            return false;
        } finally {
            await this.page.evaluate((m) => document.querySelectorAll('[' + m + ']').forEach((e) => e.removeAttribute(m)), MARK);
        }
    }

    // Click the button whose caption matches `re`.
    async clickButton(re) {
        const found = await this.page.evaluate(__markClickable, re.source || String(re), MARK);
        if (!found) return false;
        const el = await this._marked();
        if (!el) return false;
        try { await el.click(); return true; }
        catch (e) { this.log('warn', `Could not click ${re}: ${e.message}`); return false; }
        finally {
            await this.page.evaluate((m) => document.querySelectorAll('[' + m + ']').forEach((e) => e.removeAttribute(m)), MARK);
        }
    }

    // Attach real files to the site's file input (the account's own PDFs).
    async attachFiles(paths) {
        const found = await this.page.evaluate(__markFileInput, MARK);
        if (!found) return false;
        const el = await this._marked();
        if (!el) return false;
        try { await el.uploadFile(...paths); return true; }
        catch (e) { this.log('warn', `Could not attach file(s): ${e.message}`); return false; }
        finally {
            await this.page.evaluate((m) => document.querySelectorAll('[' + m + ']').forEach((e) => e.removeAttribute(m)), MARK);
        }
    }

    async pageErrors() {
        try { return await this.page.evaluate(__readErrors); } catch (e) { return []; }
    }

    // Is a captcha widget on this page at all? (If not, there's nothing to wait for.)
    async captchaPresent() {
        try {
            return await this.page.evaluate(() => !!document.querySelector(
                '[name="cf-turnstile-response"], .cf-turnstile, [class*=turnstile], ' +
                'iframe[src*="challenges.cloudflare.com"], [name="g-recaptcha-response"], ' +
                '[name="h-captcha-response"], iframe[src*="recaptcha"]'
            ));
        } catch (e) { return false; }
    }

    // Has it been solved? Every provider drops its token into a hidden response input, so a
    // non-trivial value there is the definitive "solved" signal — no clicking required from us.
    async captchaSolved() {
        try {
            return await this.page.evaluate(() => {
                const els = [...document.querySelectorAll(
                    '[name="cf-turnstile-response"], [name="g-recaptcha-response"], [name="h-captcha-response"]'
                )];
                return els.some((e) => e.value && e.value.length > 20);
            });
        } catch (e) { return false; }
    }

    // Is a field for `role` currently on screen? Used to detect which screen we're on.
    async hasField(role) {
        try {
            const f = await this.page.evaluate(__markField, role, MARK);
            await this.page.evaluate((m) => document.querySelectorAll('[' + m + ']').forEach((e) => e.removeAttribute(m)), MARK);
            return f;
        } catch (e) { return false; }
    }
}

/**
 * Run `fn` until it resolves truthy, retrying on failure with a linear backoff. Never throws
 * — returns { ok, attempts, lastError } so a failed step degrades to "do it manually" instead
 * of killing a walk that has already captured other steps.
 */
async function withRetry(name, fn, { attempts = 5, backoffMs = 4000, log = () => {}, isStopped = () => false } = {}) {
    let lastError = null;
    for (let i = 1; i <= attempts; i++) {
        if (isStopped()) return { ok: false, attempts: i - 1, lastError: 'stopped' };
        try {
            const r = await fn(i);
            if (r) return { ok: true, attempts: i, lastError: null };
            lastError = 'step did not confirm success';
        } catch (e) {
            lastError = e.message;
        }
        if (i < attempts) {
            const wait = backoffMs * i;
            log('warn', `↻ ${name} attempt ${i}/${attempts} failed (${lastError}) — retrying in ${Math.round(wait / 1000)}s`);
            await sleep(wait);
        }
    }
    log('warn', `✋ ${name} did not succeed after ${attempts} attempts (${lastError}). Do this step in the browser window — capture continues.`);
    return { ok: false, attempts, lastError };
}

module.exports = {
    SiteDriver, withRetry, sleep,
    // In-page scorers, exported so they can be exercised against a real DOM in tests.
    _inPage: { __markField, __markClickable, __markFileInput, __readErrors, MARK },
};
