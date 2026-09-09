/**
 * extractCipherFromBundle.js — Offline Cipher Extractor
 *
 * Scans every .js file in ./bundle, runs the same extraction logic
 * as cipherKeys.js (configs, keys, alphabet, native modules),
 * and writes the full results to cipher_extract_output.json.
 *
 * Usage:
 *   node extractCipherFromBundle.js [--bundle-dir ./bundle] [--out cipher_extract_output.json]
 */

'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

// ─── CLI args ─────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
function getArg(flag, def) {
    const i = args.indexOf(flag);
    return i >= 0 && args[i + 1] ? args[i + 1] : def;
}
const BUNDLE_DIR = getArg('--bundle-dir', path.join(__dirname, 'bundle'));
const OUT_FILE   = getArg('--out', path.join(__dirname, 'cipher_extract_output.json'));

// ─── Helpers (ported verbatim from cipherKeys.js) ────────────────────────────

const MODULE_END_MARKER = ',{value:"Module"}))';

function escapeRegExp(s) {
    return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function stripStringLiterals(source) {
    return String(source)
        .replace(/"(?:\\.|[^"\\])*"/g, '""')
        .replace(/'(?:\\.|[^'\\])*'/g, "''")
        .replace(/`(?:\\.|[^`\\])*`/g, '``');
}

function calleeNamesFromExpr(expr) {
    const stripped = stripStringLiterals(expr);
    const names = [];
    const re = /\b([A-Za-z_$][\w$]{1,})\s*\(/g;
    let m;
    while ((m = re.exec(stripped)) !== null) names.push(m[1]);
    return [...new Set(names)];
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
        else if (region[i] === '}') { depth--; if (depth === 0) return region.slice(idx, i + 1); }
    }
    return '';
}

function findLookupTableEnd(text, beforeIdx) {
    const start = Math.max(0, beforeIdx - 150000);
    const region = text.slice(start, beforeIdx);
    const matches = [...region.matchAll(/\}\(([A-Za-z_$][\w$]{1,6})\)/g)];
    if (!matches.length) return null;
    const last = matches[matches.length - 1];
    return { end: start + last.index + last[0].length, varName: last[1] };
}

function resolveDecoderGraph(text, callees, assignIdx, rot) {
    const fnNames = [];
    const seen = {};
    function add(name) { if (!name || seen[name]) return; seen[name] = true; fnNames.push(name); }
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
            while ((m = retRe.exec(stripped)) !== null) { if (!seen[m[1]]) { add(m[1]); changed = true; } }
            const varRe = /\bvar\s+n\s*=\s*([A-Za-z_$][\w$]{1,})\(\)/g;
            while ((m = varRe.exec(stripped)) !== null) { if (!seen[m[1]]) { add(m[1]); changed = true; } }
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
        if (block) { seen[fn] = true; out += '\n' + block; }
    }
    return out;
}

function findAlphabet(text) {
    const re = /"([^"]{60,70})"/g;
    let m;
    const candidates = [];
    while ((m = re.exec(text)) !== null) {
        const s = m[1];
        if (!s.includes('0') || !s.includes('9')) continue;
        if (!s.includes('a') || !s.includes('z')) continue;
        if (!s.includes('A') || !s.includes('Z')) continue;
        const digits = new Set(s.match(/[0-9]/g) || []);
        const lower  = new Set(s.match(/[a-z]/g) || []);
        const upper  = new Set(s.match(/[A-Z]/g) || []);
        if (digits.size >= 10 && lower.size >= 26 && upper.size >= 26) {
            const unique = new Set(s);
            if (unique.size === s.length) candidates.push({ str: s, index: m.index });
        }
    }
    if (!candidates.length) return null;
    for (const c of candidates) {
        const nearby = text.slice(Math.max(0, c.index - 5000), Math.min(text.length, c.index + 5000));
        if (/startAt:\d+,length:\d+/.test(nearby) || /encryptText|encrypt\(/.test(nearby)) return c.str;
    }
    return candidates[0].str;
}

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

function findCipherConfigs(text) {
    const re = /const\s+([A-Za-z_$][\w$]{0,15})=\{secret:((?:[^"{}]|"(?:\\.|[^"\\])*")*?),startAt:(\d+),length:(\d+),version:(\d+)\}/g;
    const results = [];
    let match;
    while ((match = re.exec(text)) !== null) {
        const keyVar    = match[1];
        const secretExpr = match[2].trim();
        const startAt   = parseInt(match[3], 10);
        const length    = parseInt(match[4], 10);
        const version   = parseInt(match[5], 10);
        if (startAt <= 0 || startAt >= 50 || length <= 0 || length >= 100) continue;
        const ctxStart = Math.max(0, match.index - 3000);
        const ctxEnd   = Math.min(text.length, match.index + 12000);
        const ctx = text.slice(ctxStart, ctxEnd);
        let flow = 'unknown';
        if (isSignInFlow(ctx)) flow = 'signin';
        else if (isReserveSlotFlow(ctx)) flow = 'reserve';
        results.push({ keyVar, secretExpr, startAt, length, version, flow, index: match.index, fullMatch: match[0] });
    }
    return results;
}

function parsePlaintextSecret(text, keyVar) {
    const re = new RegExp(
        'const\\s+' + escapeRegExp(keyVar) +
        '=\\{secret:"((?:\\\\.|[^"\\\\])*)",startAt:(\\d+),length:(\\d+),version:(\\d+)\\}'
    );
    const m = text.match(re);
    if (!m) return null;
    try { return JSON.parse('"' + m[1] + '"'); } catch (_) { return null; }
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
    const assignIdx  = text.indexOf(configLine);
    if (assignIdx < 0) return null;
    const rot = findLookupTableEnd(text, assignIdx);
    if (!rot) return null;
    const fnNames = resolveDecoderGraph(text, calleeNamesFromExpr(secretExpr), assignIdx, rot);
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
    return head + beforeConfig + tail + '\n' + configLine + '\nRESULT=' + keyVar + '.secret;\n';
}

function buildSectionEval(text, keyVar, configIdx) {
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
    const baseName = baseTable.name;
    const wrapperRe = new RegExp(
        `\\bfunction\\s+([A-Za-z_$][\\w$]{0,10})\\s*\\(e(?:,t)?\\)\\s*\\{[^}]{0,200}\\b${escapeRegExp(baseName)}\\s*\\(`, 'g'
    );
    const wrapSearchStart = Math.max(searchLimit, baseTable.pos - 10000);
    const wrapSearchEnd   = Math.min(configIdx + 10000, text.length);
    const wrapRegion = text.slice(wrapSearchStart, wrapSearchEnd);
    let earliestWrapperPos = baseTable.pos;
    wrapperRe.lastIndex = 0;
    while ((m = wrapperRe.exec(wrapRegion)) !== null) {
        const absPos = wrapSearchStart + m.index;
        if (absPos < baseTable.pos && absPos < earliestWrapperPos) earliestWrapperPos = absPos;
    }
    const configRe = new RegExp(
        `(?:const|var|let)\\s+${escapeRegExp(keyVar)}\\s*=\\s*\\{secret:((?:[^"{}]|"(?:\\\\.|[^"\\\\])*")*)?,startAt:(\\d+),length:(\\d+),version:(\\d+)\\}`
    );
    const configMatch = configRe.exec(text.slice(configIdx, configIdx + 3000));
    if (!configMatch) {
        const fallbackLineEnd = text.indexOf('\n', configIdx);
        const configLineEnd   = fallbackLineEnd > 0 ? fallbackLineEnd : configIdx + 3000;
        const sectionStart    = Math.min(earliestWrapperPos, baseTable.pos);
        const section = text.slice(sectionStart, configLineEnd + 1);
        const resultVar = '__CIPHER_RESULT_' + keyVar + '__';
        return `(function() {\n${section}\nvar ${resultVar} = typeof ${keyVar} !== 'undefined' ? ${keyVar} : null;\nreturn ${resultVar};\n})()`;
    }
    const configEnd       = configIdx + configMatch.index + configMatch[0].length;
    const configMatchText = configMatch[0];
    const iifeSearchWindow = text.slice(Math.max(searchLimit, earliestWrapperPos - 2000), configIdx);
    const iifeEndPattern   = `}(${baseName})`;
    const iifeEndInWindow  = iifeSearchWindow.lastIndexOf(iifeEndPattern);
    if (iifeEndInWindow >= 0) {
        const beforeIifeEnd    = iifeSearchWindow.slice(0, iifeEndInWindow);
        const iifeOpenInWindow = beforeIifeEnd.lastIndexOf('!function(e){');
        if (iifeOpenInWindow >= 0) {
            const iifeAbsStart = Math.max(searchLimit, earliestWrapperPos - 2000) + iifeOpenInWindow;
            if (iifeAbsStart < earliestWrapperPos) earliestWrapperPos = iifeAbsStart;
        }
    }
    const sectionStart = Math.min(earliestWrapperPos, baseTable.pos);
    let sectionEnd = configEnd;
    const secretExprMatch = configMatchText.match(/secret:(.*?),startAt:\d+/s);
    const secretExprRaw   = secretExprMatch ? secretExprMatch[1] : configMatchText;
    const calleesInSecret = calleeNamesFromExpr(secretExprRaw);
    const forwardRegion   = text.slice(configEnd, configEnd + 8000);
    for (const callee of calleesInSecret) {
        const simpleDeclRe = new RegExp(`\\bfunction\\s+${escapeRegExp(callee)}\\s*\\(e(?:,t)?\\)\\{return\\s+[A-Za-z_$][\\w$]*\\(`);
        const fnDeclMatch = simpleDeclRe.exec(forwardRegion);
        if (fnDeclMatch) {
            const openBracePos = forwardRegion.indexOf('{', fnDeclMatch.index);
            let depth = 0, closeBracePos = -1;
            for (let i = openBracePos; i < forwardRegion.length; i++) {
                if (forwardRegion[i] === '{') depth++;
                else if (forwardRegion[i] === '}') { depth--; if (depth === 0) { closeBracePos = i; break; } }
            }
            const endPos = closeBracePos >= 0 ? closeBracePos + 1 : fnDeclMatch.index + 100;
            const newEnd = configEnd + endPos;
            if (newEnd > sectionEnd) sectionEnd = newEnd;
        }
    }
    const section   = text.slice(sectionStart, sectionEnd);
    const resultVar = '__CIPHER_RESULT_' + keyVar + '__';
    return `(function() {\n${section}\nvar ${resultVar} = typeof ${keyVar} !== 'undefined' ? ${keyVar} : null;\nreturn ${resultVar};\n})()`;
}

function evaluateSecret(text, configEntry) {
    const plain = parsePlaintextSecret(text, configEntry.keyVar);
    if (plain) return { key: plain, strategy: 'plaintext', err: null };

    const sectionScript = buildSectionEval(text, configEntry.keyVar, configEntry.index);
    if (sectionScript) {
        try {
            const sandbox = { decodeURIComponent, encodeURIComponent, String, Math, parseInt, parseFloat, Array, Object, RegExp, Error, Boolean, Number };
            const result = vm.runInContext(sectionScript, vm.createContext(sandbox), { timeout: 5000 });
            if (result && result.secret) {
                const key = String(result.secret).trim();
                if (key) return { key, strategy: 'section-eval', err: null };
            }
        } catch (e) {
            // fall through to strategy 2
        }
    }

    const script = buildProfileKeyEval(text, configEntry.keyVar);
    if (!script) return { key: null, strategy: null, err: 'Could not build key eval script for ' + configEntry.keyVar };
    try {
        const sandbox = { RESULT: '' };
        vm.runInContext(script, vm.createContext(sandbox), { timeout: 5000 });
        const key = String(sandbox.RESULT || '').trim();
        if (key) return { key, strategy: 'profile-eval', err: null };
        return { key: null, strategy: 'profile-eval', err: 'Key empty after vm eval' };
    } catch (e) {
        return { key: null, strategy: 'profile-eval', err: `vm eval error: ${e.message}` };
    }
}

function extractCipherModules(bundleText) {
    const versionMap = {};
    const mapEntryRe = /(\d{1,3}):\(\)=>[A-Za-z_$][\w$]*\(\(\)=>Promise\.resolve\(\)\.then\(\(\)=>([A-Za-z_$][\w$]*)\)\)/g;
    let me;
    while ((me = mapEntryRe.exec(bundleText)) !== null) versionMap[me[1]] = me[2];

    const exportRe = /([A-Za-z_$][\w$]*)=Object\.freeze\(Object\.defineProperty\(\{(?:__proto__:null,)?decryptText:([A-Za-z_$][\w$]*),encryptText:([A-Za-z_$][\w$]*)\}/g;
    const exportsByVar = {};
    let em;
    while ((em = exportRe.exec(bundleText)) !== null) {
        const exportVar = em[1], decFn = em[2], encFn = em[3];
        const endMarkerPos = bundleText.indexOf(MODULE_END_MARKER, em.index);
        if (endMarkerPos < 0) continue;
        const moduleEnd  = endMarkerPos + MODULE_END_MARKER.length;
        const prevMarkerPos = bundleText.lastIndexOf(MODULE_END_MARKER, em.index - 1);
        const moduleStart   = prevMarkerPos < 0 ? 0 : prevMarkerPos + MODULE_END_MARKER.length;
        const section = bundleText.slice(moduleStart, moduleEnd);
        const code = `(function(){\n${section}\nreturn {encryptText: typeof ${encFn}!=='undefined'?${encFn}:null, decryptText: typeof ${decFn}!=='undefined'?${decFn}:null};\n})()`;
        exportsByVar[exportVar] = { encFn, decFn, code };
    }
    if (Object.keys(exportsByVar).length === 0) return null;

    const modulesByVersion = {};
    if (Object.keys(versionMap).length > 0) {
        for (const [version, exportVar] of Object.entries(versionMap)) {
            if (exportsByVar[exportVar]) modulesByVersion[version] = exportsByVar[exportVar].code;
        }
    } else {
        let i = 1;
        for (const exportVar of Object.keys(exportsByVar)) modulesByVersion[String(i++)] = exportsByVar[exportVar].code;
    }
    return { versionMap, modulesByVersion, exportsByVar };
}

function evalModuleCode(code) {
    const sandbox = { decodeURIComponent, encodeURIComponent, String, Math, parseInt, parseFloat, Array, Object, RegExp, Error, Boolean, Number, Symbol, BigInt, JSON, isNaN, isFinite };
    const result = vm.runInContext(code, vm.createContext(sandbox), { timeout: 10000 });
    if (result && typeof result.encryptText === 'function' && typeof result.decryptText === 'function') return true;
    return false;
}

// ─── Main ────────────────────────────────────────────────────────────────────

function log(msg) { process.stdout.write(msg + '\n'); }

function processBundleFile(filePath) {
    const filename = path.basename(filePath);
    const text = fs.readFileSync(filePath, 'utf8');
    log(`  [${filename}] size=${(text.length / 1024).toFixed(1)}KB`);

    const result = {
        file: filename,
        path: filePath,
        sizeBytes: text.length,
        alphabet: null,
        configs: [],
        modules: null,
    };

    // Alphabet
    const alphabet = findAlphabet(text);
    if (alphabet) {
        result.alphabet = alphabet;
        log(`    alphabet: "${alphabet.slice(0, 20)}..." (${alphabet.length} chars)`);
    }

    // Cipher configs + key extraction
    const configs = findCipherConfigs(text);
    log(`    configs found: ${configs.length}`);
    for (const cfg of configs) {
        const evalResult = evaluateSecret(text, cfg);
        const entry = {
            keyVar:    cfg.keyVar,
            flow:      cfg.flow,
            startAt:   cfg.startAt,
            length:    cfg.length,
            version:   cfg.version,
            secretExpr: cfg.secretExpr.slice(0, 80) + (cfg.secretExpr.length > 80 ? '...' : ''),
            key:       evalResult.key || null,
            strategy:  evalResult.strategy || null,
            evalError: evalResult.err || null,
        };
        log(`    ${cfg.keyVar} flow=${cfg.flow} v${cfg.version} startAt=${cfg.startAt} len=${cfg.length} → key=${evalResult.key ? evalResult.key.slice(0, 14) + '...' : '(failed: ' + (evalResult.err || '?') + ')'}`);
        result.configs.push(entry);
    }

    // Native cipher modules
    const modulesData = extractCipherModules(text);
    if (modulesData) {
        const versions = Object.keys(modulesData.modulesByVersion);
        // Validate each module evaluates correctly
        const validVersions = [];
        for (const [ver, code] of Object.entries(modulesData.modulesByVersion)) {
            try {
                const ok = evalModuleCode(code);
                if (ok) validVersions.push(ver);
            } catch (_) {}
        }
        result.modules = {
            versionMap: modulesData.versionMap,
            versionsFound: versions,
            versionsValid: validVersions,
            exportVars: Object.keys(modulesData.exportsByVar),
        };
        log(`    native modules: versions=[${versions.join(',')}] valid=[${validVersions.join(',')}]`);
    } else {
        log(`    native modules: none found`);
    }

    return result;
}

function main() {
    log(`\n=== extractCipherFromBundle.js ===`);
    log(`Bundle dir : ${BUNDLE_DIR}`);
    log(`Output file: ${OUT_FILE}`);
    log('');

    if (!fs.existsSync(BUNDLE_DIR)) {
        log(`ERROR: bundle directory not found: ${BUNDLE_DIR}`);
        process.exit(1);
    }

    const files = fs.readdirSync(BUNDLE_DIR)
        .filter(f => f.endsWith('.js'))
        .map(f => path.join(BUNDLE_DIR, f));

    if (!files.length) {
        log(`ERROR: no .js files found in ${BUNDLE_DIR}`);
        process.exit(1);
    }

    log(`Found ${files.length} JS file(s):`);

    const output = {
        extractedAt: new Date().toISOString(),
        bundleDir: BUNDLE_DIR,
        files: [],
        summary: {
            totalFiles: files.length,
            filesWithConfigs: 0,
            filesWithModules: 0,
            allConfigs: [],
            bestSignin: null,
            bestReserve: null,
        },
    };

    for (const filePath of files) {
        const result = processBundleFile(filePath);
        output.files.push(result);
        if (result.configs.length > 0) output.summary.filesWithConfigs++;
        if (result.modules)            output.summary.filesWithModules++;
        for (const cfg of result.configs) {
            output.summary.allConfigs.push({ ...cfg, fromFile: result.file });
        }
    }

    // Pick best signin / reserve across all files
    const all = output.summary.allConfigs.filter(c => c.key);
    const signinCandidates  = all.filter(c => c.flow === 'signin');
    const reserveCandidates = all.filter(c => c.flow === 'reserve');
    const unknownCandidates = all.filter(c => c.flow === 'unknown');

    output.summary.bestSignin  = signinCandidates[0]  || unknownCandidates[0]  || null;
    output.summary.bestReserve = reserveCandidates[0] || unknownCandidates[1]  || null;

    log('');
    log('─── Summary ───────────────────────────────────────────');
    log(`Files scanned   : ${output.summary.totalFiles}`);
    log(`Files w/ configs: ${output.summary.filesWithConfigs}`);
    log(`Files w/ modules: ${output.summary.filesWithModules}`);
    if (output.summary.bestSignin) {
        const s = output.summary.bestSignin;
        log(`Best signin key : ${s.key.slice(0, 14)}... (v${s.version}, startAt=${s.startAt}, len=${s.length}, from ${s.fromFile})`);
    } else {
        log(`Best signin key : NOT FOUND`);
    }
    if (output.summary.bestReserve) {
        const r = output.summary.bestReserve;
        log(`Best reserve key: ${r.key.slice(0, 14)}... (v${r.version}, startAt=${r.startAt}, len=${r.length}, from ${r.fromFile})`);
    } else {
        log(`Best reserve key: NOT FOUND`);
    }

    fs.writeFileSync(OUT_FILE, JSON.stringify(output, null, 2), 'utf8');
    log('');
    log(`Output written to: ${OUT_FILE}`);
    log('');
}

main();
