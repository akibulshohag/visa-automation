/**
 * cipherAst.js — Universal cipher-secret extractor (AST-based).
 *
 * WHY THIS EXISTS
 * ---------------
 * The IVAC bundle obfuscates the captcha secret so it can only be produced by RUNNING the
 * site's own decoder machine (a rotated string-array + RC4/base64 decoders). The older
 * extractor in cipherKeys.js reconstructs a runnable slice of that machine with regex +
 * character-window heuristics ("grab 3500 chars back", "stop at `}static`", …). Every time
 * IVAC re-obfuscates — which is happening ~daily — the code LAYOUT changes and those window
 * guesses emit broken JS ("Unexpected token ')'") → "Could not build key eval script".
 *
 * This module removes the guessing. It parses the bundle into a real AST and follows the
 * REFERENCE GRAPH: starting from the secret expression, it resolves every identifier against
 * true lexical scopes, pulls in each binding's declaration as a COMPLETE ast node (never a
 * truncated slice), recurses until the graph is closed, adds the string-array rotation
 * side-effect, and evaluates that in a vm sandbox. Because it follows references — not byte
 * positions — renaming and reshuffling by the obfuscator no longer matter. It only breaks if
 * IVAC changes the fundamental scheme (e.g. server-issued secret or WASM crypto), which no
 * static approach survives anyway.
 *
 * Validated end-to-end against bundle mrhfgwht-* (2026-07-13): both cipher configs resolve to
 * the same 64-char secret and the encrypt→decrypt roundtrip passes.
 */

const vm = require('vm');
const acorn = require('acorn');

// ─── Parse ───────────────────────────────────────────────────────────────────
function parseBundle(src) {
    // The bundle is a Vite ESM chunk; try module first, then script as a fallback.
    for (const sourceType of ['module', 'script']) {
        try {
            return acorn.parse(src, { ecmaVersion: 'latest', sourceType, allowReturnOutsideFunction: true });
        } catch (e) {
            if (sourceType === 'script') throw e;
        }
    }
}

// ─── Tiny AST utilities ────────────────────────────────────────────────────────
function isFn(n) {
    return n.type === 'FunctionDeclaration' || n.type === 'FunctionExpression' || n.type === 'ArrowFunctionExpression';
}

// Visit the direct child AST nodes of `node`.
function eachChild(node, fn) {
    for (const k in node) {
        if (k === 'type' || k === 'start' || k === 'end' || k === '__scope') continue;
        const v = node[k];
        if (Array.isArray(v)) { for (const c of v) if (c && typeof c.type === 'string') fn(c); }
        else if (v && typeof v.type === 'string') fn(v);
    }
}

// Names a binding target (Identifier / destructuring pattern) introduces.
function patternNames(node, out) {
    if (!node) return;
    switch (node.type) {
        case 'Identifier': out.push(node.name); break;
        case 'ObjectPattern': for (const p of node.properties) patternNames(p.value || p.argument, out); break;
        case 'ArrayPattern': for (const e of node.elements) e && patternNames(e, out); break;
        case 'AssignmentPattern': patternNames(node.left, out); break;
        case 'RestElement': patternNames(node.argument, out); break;
    }
}

// ─── Scope model ───────────────────────────────────────────────────────────────
// A scope is created for Program + every function-like node. `bindings` maps each name
// declared DIRECTLY in that scope (functions, vars, params, class ids) to its declaration
// node — without descending into nested function scopes (those get their own scope).
function makeScope(node, parent) { return { node, parent, bindings: new Map() }; }

function collectBindings(scope, bodyNode) {
    const visit = (n) => {
        if (!n) return;
        // A nested function contributes only its NAME to this scope; its body is a
        // different scope, so don't descend into it here.
        if (isFn(n)) { if (n.type === 'FunctionDeclaration' && n.id) scope.bindings.set(n.id.name, n); return; }
        switch (n.type) {
            case 'ClassDeclaration': if (n.id) scope.bindings.set(n.id.name, n); return;
            case 'VariableDeclaration':
                for (const d of n.declarations) {
                    const names = []; patternNames(d.id, names);
                    for (const nm of names) scope.bindings.set(nm, d);
                }
                break;
        }
        eachChild(n, visit);
    };
    // The scope function's own params + name bind in this scope.
    if (isFn(scope.node)) {
        for (const p of scope.node.params) { const names = []; patternNames(p, names); for (const nm of names) scope.bindings.set(nm, scope.node); }
        if (scope.node.type === 'FunctionDeclaration' && scope.node.id) scope.bindings.set(scope.node.id.name, scope.node);
    }
    const body = (bodyNode.type === 'BlockStatement' || bodyNode.type === 'Program') ? bodyNode.body : [bodyNode];
    for (const s of (Array.isArray(body) ? body : [body])) visit(s);
}

// Build every scope, tag each node with the scope it lives in (`__scope`), and collect the
// rotation side-effects (see below).
function buildModel(ast) {
    const rotations = []; // { node, argNames:Set } — string-array shuffle IIFEs
    (function walk(node, parentScope) {
        let scope = parentScope;
        if (node.type === 'Program' || isFn(node)) {
            scope = makeScope(node, parentScope);
            collectBindings(scope, node.type === 'Program' ? node : node.body);
        }
        node.__scope = scope;
        // A rotation is `!function(e){…}(ARR)` / `fn(ARR)` as a statement: it reorders the
        // obfuscator string array at load. It lives inside the module closure, so we scan at
        // every depth (not just Program level). We don't filter by arg name here — the caller
        // keeps only the one whose argument is the string-array function it actually collected.
        if (node.type === 'ExpressionStatement') {
            let expr = node.expression;
            while (expr && expr.type === 'UnaryExpression') expr = expr.argument;
            if (expr && expr.type === 'CallExpression') {
                const argNames = new Set();
                for (const a of expr.arguments) if (a.type === 'Identifier') argNames.add(a.name);
                if (argNames.size) rotations.push({ node, argNames });
            }
        }
        eachChild(node, (c) => walk(c, scope));
    })(ast, null);
    return { rotations };
}

function resolveName(name, fromScope) {
    for (let s = fromScope; s; s = s.parent) if (s.bindings.has(name)) return s.bindings.get(name);
    return null;
}

// Names that are language/host globals — never treated as things to collect.
const BUILTINS = new Set(['String', 'Math', 'parseInt', 'parseFloat', 'Array', 'Object', 'RegExp',
    'Error', 'Boolean', 'Number', 'Symbol', 'BigInt', 'JSON', 'isNaN', 'isFinite', 'decodeURIComponent',
    'encodeURIComponent', 'undefined', 'null', 'true', 'false', 'NaN', 'Infinity', 'this', 'arguments',
    'Date', 'Function', 'Promise', 'Set', 'Map', 'WeakMap', 'globalThis', 'window', 'document', 'console']);

// Visit every Identifier used at a VALUE (reference) position inside `root`, calling cb.
// Skips non-reference positions: non-computed member props (`.foo`), non-computed object keys
// (`foo:`), and binding-id positions (declarator ids, plain params, function/class names).
function eachRef(root, cb) {
    (function walk(n) {
        if (!n || typeof n.type !== 'string') return;
        switch (n.type) {
            case 'Identifier': cb(n); return;
            case 'MemberExpression': walk(n.object); if (n.computed) walk(n.property); return;
            case 'Property': if (n.computed) walk(n.key); walk(n.value); return;
            case 'MethodDefinition': case 'PropertyDefinition': if (n.computed) walk(n.key); if (n.value) walk(n.value); return;
            case 'VariableDeclarator': if (n.id && n.id.type !== 'Identifier') walk(n.id); if (n.init) walk(n.init); return;
            case 'FunctionDeclaration': case 'FunctionExpression': case 'ArrowFunctionExpression':
                for (const p of n.params) walk(p); if (n.body) walk(n.body); return;
            case 'LabeledStatement': walk(n.body); return;
            case 'BreakStatement': case 'ContinueStatement': return;
        }
        eachChild(n, walk);
    })(root);
}

// Is `fnDecl` the obfuscator's string-array function? i.e. its body declares a big array of
// string literals. This structural signature is stable across builds.
function isStringArrayFn(fnDecl) {
    if (fnDecl.type !== 'FunctionDeclaration' || !fnDecl.body) return false;
    let found = false;
    (function scan(n) {
        if (found || !n || typeof n.type !== 'string') return;
        if (n.type === 'ArrayExpression' && n.elements.length >= 20 &&
            n.elements.filter(e => e && e.type === 'Literal' && typeof e.value === 'string').length >= 20) { found = true; return; }
        eachChild(n, scan);
    })(fnDecl.body);
    return found;
}

// ─── Secret evaluation ────────────────────────────────────────────────────────
// Follow the reference closure from `secretExprNode`, assemble the needed declarations +
// the string-array rotation, and evaluate the secret in a vm sandbox.
function evalSecret(code, secretExprNode, allRotations) {
    const collected = new Map(); // declNode -> true
    const within = (decl, root) => decl.start >= root.start && decl.end <= root.end;

    const frontier = [secretExprNode];
    while (frontier.length) {
        const node = frontier.pop();
        eachRef(node, (ident) => {
            if (BUILTINS.has(ident.name)) return;
            const decl = resolveName(ident.name, ident.__scope);
            if (!decl) return;              // global helper / undefined — skip
            if (within(decl, node)) return; // bound locally inside this node — not a free var
            if (collected.has(decl)) return;
            collected.set(decl, true);
            frontier.push(decl);
        });
    }

    // Keep ONLY the string-array rotation(s): statements passing a collected string-array
    // function as an argument. (Matching arbitrary collected names would drag in unrelated
    // single-letter calls all over the bundle.)
    const arrayFnNames = new Set();
    for (const d of collected.keys()) if (isStringArrayFn(d) && d.id) arrayFnNames.add(d.id.name);
    const rotations = [];
    for (const rot of allRotations) for (const an of rot.argNames) if (arrayFnNames.has(an)) { rotations.push(rot.node); break; }

    // Emit: function declarations first (hoisted), then remaining statements + rotations in
    // source order (reproducing the site's own execution order for those pieces), then read
    // the secret. Slicing by node start/end guarantees each piece is syntactically complete.
    const src = (n) => code.slice(n.start, n.end);
    const nodes = [...collected.keys(), ...rotations];
    const fns = nodes.filter(n => n.type === 'FunctionDeclaration').sort((a, b) => a.start - b.start);
    const rest = nodes.filter(n => n.type !== 'FunctionDeclaration').sort((a, b) => a.start - b.start);
    const stmt = (n) => n.type === 'VariableDeclarator' ? ('var ' + src(n) + ';') : (src(n) + ';');

    const pieces = [];
    for (const n of fns) pieces.push(src(n));
    for (const n of rest) pieces.push(stmt(n));
    pieces.push('RESULT = (' + src(secretExprNode) + ');');
    const script = '(function(){\n' + pieces.join('\n') + '\n}).call(this)';

    const sandbox = {
        RESULT: undefined, String, Math, parseInt, parseFloat, Array, Object, RegExp, Error,
        Boolean, Number, Symbol, BigInt, JSON, isNaN, isFinite, decodeURIComponent, encodeURIComponent, Date,
    };
    const ctx = vm.createContext(sandbox);
    vm.runInContext(script, ctx, { timeout: 4000 });
    const key = sandbox.RESULT == null ? '' : String(sandbox.RESULT).trim();
    return key || null;
}

// ─── Numeric field reading (startAt / length / version) ────────────────────────
// Values look like Number("1"), e.AURJO(Number,"27"), c[d(713,"j&v5")](_0x…,"2"). The real
// value is the LAST quoted integer in the expression; a bare numeric literal is the fallback.
function fieldNumber(code, valueNode) {
    const s = code.slice(valueNode.start, valueNode.end);
    const quoted = [...s.matchAll(/"(\d{1,4})"|'(\d{1,4})'/g)];
    if (quoted.length) { const q = quoted[quoted.length - 1]; return parseInt(q[1] != null ? q[1] : q[2], 10); }
    if (valueNode.type === 'Literal' && typeof valueNode.value === 'number') return valueNode.value;
    const bare = s.match(/-?\d{1,4}/);
    return bare ? parseInt(bare[0], 10) : NaN;
}

// ─── Config discovery ──────────────────────────────────────────────────────────
// Find `NAME={secret:<expr>,startAt:…,length:…,version:…}` object literals (the shape the
// site uses for each cipher config) and resolve each secret.
function extractConfigs(code, ast, model) {
    const configs = [];
    const propKey = (p) => p.key && (p.key.name != null ? p.key.name : p.key.value);
    (function find(node, keyVar) {
        if (node.type === 'VariableDeclarator' && node.id && node.id.type === 'Identifier') keyVar = node.id.name;
        if (node.type === 'ObjectExpression') {
            const props = node.properties.filter(p => p.type === 'Property');
            const sp = props.find(p => propKey(p) === 'secret');
            const ap = props.find(p => propKey(p) === 'startAt');
            const lp = props.find(p => propKey(p) === 'length');
            const vp = props.find(p => propKey(p) === 'version');
            if (sp && ap && vp) {
                let secret = null, err = null;
                try { secret = evalSecret(code, sp.value, model.rotations); }
                catch (e) { err = e.message.slice(0, 140); }
                configs.push({
                    keyVar: keyVar || null,
                    secret,
                    err,
                    startAt: fieldNumber(code, ap.value),
                    length: lp ? fieldNumber(code, lp.value) : NaN,
                    version: fieldNumber(code, vp.value),
                    start: node.start,
                });
            }
        }
        eachChild(node, (c) => find(c, keyVar));
    })(ast, null);
    return configs;
}

// ─── Public API (memoized per bundle text) ─────────────────────────────────────
let _memo = { text: null, configs: null };

function getConfigs(text) {
    if (_memo.text === text) return _memo.configs;
    let configs = [];
    try {
        const ast = parseBundle(text);
        const model = buildModel(ast);
        configs = extractConfigs(text, ast, model);
    } catch (e) {
        configs = { error: e.message };
    }
    _memo = { text, configs: Array.isArray(configs) ? configs : [] };
    return _memo.configs;
}

/**
 * Resolve the secret for one config that the caller found by regex (configEntry has
 * `.keyVar` and byte offset `.index`). Returns the secret string, or null if the AST path
 * couldn't produce one (the caller then falls back to the legacy heuristics).
 */
function secretFor(text, configEntry) {
    const configs = getConfigs(text);
    if (!configs.length) return null;
    const want = configEntry.keyVar;
    const idx = configEntry.index != null ? configEntry.index : 0;
    // Prefer a same-keyVar config; among candidates, the one whose object starts closest to
    // the regex match. Fall back to the positionally-closest config of any name.
    const named = configs.filter(c => c.keyVar === want && c.secret);
    const pool = named.length ? named : configs.filter(c => c.secret);
    if (!pool.length) return null;
    pool.sort((a, b) => Math.abs(a.start - idx) - Math.abs(b.start - idx));
    return pool[0].secret;
}

module.exports = { getConfigs, secretFor, _internals: { parseBundle, buildModel, extractConfigs } };
