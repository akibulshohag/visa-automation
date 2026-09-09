// Quick fingerprint probe — mirrors api.js _getSession() config and hits tls.peet.ws.
// Run: node fp-probe.js   (direct connection, no proxy)
const httpcloak = require('httpcloak');

const PRESET = process.env.FP_PRESET || 'chrome-149-windows';
const URL = 'https://tls.peet.ws/api/all';

async function probe(httpVersion) {
    const opts = {
        preset: PRESET,
        httpVersion,
        timeout: 30,
        verify: false,
        quicIdleTimeout: 60,
        preferIpv4: true,
    };
    // ECH only works against Cloudflare-fronted hosts; tls.peet.ws rejects it. Enable with FP_ECH=1.
    if (process.env.FP_ECH === '1') opts.echConfigDomain = 'cloudflare-ech.com';
    let session = null;
    try {
        session = new httpcloak.Session(opts);
        const res = await session.request('GET', URL, {
            headers: { 'accept': 'application/json' },
        });
        const data = JSON.parse(res.text || '{}');
        const tls = data.tls || {};
        const http2 = data.http2 || {};
        console.log(`\n=== ${PRESET} | forced ${httpVersion} ===`);
        console.log('negotiated http   :', data.http_version);
        console.log('user-agent (seen) :', (data.http1 && data.http1.headers && data.http1.headers['User-Agent']) || data.user_agent || 'n/a');
        console.log('JA3               :', tls.ja3);
        console.log('JA3 hash          :', tls.ja3_hash);
        console.log('JA4               :', tls.ja4);
        console.log('peetprint hash    :', tls.peetprint_hash);
        if (http2.akamai_fingerprint) {
            console.log('akamai h2 fp      :', http2.akamai_fingerprint);
            console.log('akamai h2 hash    :', http2.akamai_fingerprint_hash);
        }
        if (data.tls && data.tls.ja4_r) console.log('JA4_r             :', data.tls.ja4_r);
    } catch (e) {
        console.log(`\n=== ${PRESET} | forced ${httpVersion} === FAILED: ${e.message}`);
    } finally {
        if (session) { try { session.close(); } catch (e) {} }
    }
}

(async () => {
    await probe('h2');
    await probe('h3');
    console.log('\nCompare the JA3/JA4/peetprint above against a real Chrome at https://tls.peet.ws/api/all');
    process.exit(0);
})();
