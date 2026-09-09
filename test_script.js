const ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_';
const ALPHA_LEN = ALPHABET.length; // 64

const RESERVE_SLOT_KEY = 'm%@7*sya1v=)6s^s+easbztw011h(neb$etq9i^pt(!80!*n6(';
const RESERVE_SLOT_PREFIX_LEN = 6;
const RESERVE_SLOT_ENCODE_LEN = 17;

function rc4Stream(key, count) {
    const S = Array.from({ length: ALPHA_LEN }, (_, i) => i);
    let j = 0;
    for (let i = 0; i < ALPHA_LEN; i++) {
        j = (j + S[i] + key.charCodeAt(i % key.length)) % ALPHA_LEN;
        [S[i], S[j]] = [S[j], S[i]];
    }
    let ci = 0;
    j = 0;
    const stream = [];
    for (let k = 0; k < count; k++) {
        ci = (ci + 1) % ALPHA_LEN;
        j = (j + S[ci]) % ALPHA_LEN;
        [S[ci], S[j]] = [S[j], S[ci]];
        stream.push(S[(S[ci] + S[j]) % ALPHA_LEN]);
    }
    return stream;
}

function encryptReserveSlotCaptcha(plain, key, prefixLen, encodeLen) {
    const a = Math.max(0, Math.min(prefixLen, plain.length));
    const c = Math.max(0, plain.length - a);
    const s = Math.max(0, Math.min(encodeLen, c));
    if (s === 0) return plain;

    const stream = rc4Stream(key, s);
    const middle = plain.slice(a, a + s).split('');

    for (let p = 0; p < middle.length; p++) {
        const idx = ALPHABET.indexOf(middle[p]);
        if (idx !== -1) {
            middle[p] = ALPHABET[(idx + stream[p]) % ALPHA_LEN];
        }
    }
    return plain.slice(0, a) + middle.join('') + plain.slice(a + s);
}

const raw = "1.OV0tY3kcxbEcpBQQyDigHlMxt11aTeoHdRj7QifnIH7Hfy8e5Z1r1AmddYYbC80WmsG5JUxc3txeblWvkclQaG7ZjlGAFs0TFni_PUcWdSqeIhspX-6jjlsX0T37HD4jNQaBT7OmFPRweUN2fwPUv5-RpXLRfKOK8sbd3a7G07FKK-3qpu9ne6S8o_db1ZjqKBtcCAUfKHWVZg2iA-IsXE4VO6nZjtAGilk5gt-fru0Vemdb1crvX3usY-zoBmf9luOth2ktiFwAMj6CUlXMRqEHLqDQOr9iOjTe0otRCK_Y8zXyRUJ7KjmN_-txEAqgmNzgTmxTeDicbVcZBXLAYGBlCUvypkTK62MuzgvJ-OymzciouPG2bKWBfqcII1X5r-rApUQ_Ngb5dlwnaiiZr7FH5Y-DbNeq43AQK3lylTxxA0iZEwFoeHZqAprD7v20EVnRD6setcUsvsXNRcsT1GJtLaErWqfYZMB_8XeAmVNbxknxlbvOr8lv4wuwePJf8bB4oaMchUz0JAK9wPOZOv8mAqjgA5TBc9V79E3uzSj2cidUN9Zvz4ET3TMBxro-Z99Oo4P7HMxllPZAeeo1H0ufktVDU8G8IAKArGS2hr5tN6PVMD69bHQ7QO_RKMEuhbLszRc4e390fvfqshj1bfmlagNBBvUFhsZKSwqwHdhk7Yp9gSbfxeZ5xZY14R_jxwJw4HB-Rc-DzS_qxmoA2w.KARn_yDmY4pQf5PEF4PSLA.f8078c7bb548cacf44639c41c40ce50af5f88287ab56d7eab2e15aec1d1221a7";

const expectedEncoded = "1.OV0t-BmYjua7mKttWyy3olMxt11aTeoHdRj7QifnIH7Hfy8e5Z1r1AmddYYbC80WmsG5JUxc3txeblWvkclQaG7ZjlGAFs0TFni_PUcWdSqeIhspX-6jjlsX0T37HD4jNQaBT7OmFPRweUN2fwPUv5-RpXLRfKOK8sbd3a7G07FKK-3qpu9ne6S8o_db1ZjqKBtcCAUfKHWVZg2iA-IsXE4VO6nZjtAGilk5gt-fru0Vemdb1crvX3usY-zoBmf9luOth2ktiFwAMj6CUlXMRqEHLqDQOr9iOjTe0otRCK_Y8zXyRUJ7KjmN_-txEAqgmNzgTmxTeDicbVcZBXLAYGBlCUvypkTK62MuzgvJ-OymzciouPG2bKWBfqcII1X5r-rApUQ_Ngb5dlwnaiiZr7FH5Y-DbNeq43AQK3lylTxxA0iZEwFoeHZqAprD7v20EVnRD6setcUsvsXNRcsT1GJtLaErWqfYZMB_8XeAmVNbxknxlbvOr8lv4wuwePJf8bB4oaMchUz0JAK9wPOZOv8mAqjgA5TBc9V79E3uzSj2cidUN9Zvz4ET3TMBxro-Z99Oo4P7HMxllPZAeeo1H0ufktVDU8G8IAKArGS2hr5tN6PVMD69bHQ7QO_RKMEuhbLszRc4e390fvfqshj1bfmlagNBBvUFhsZKSwqwHdhk7Yp9gSbfxeZ5xZY14R_jxwJw4HB-Rc-DzS_qxmoA2w.KARn_yDmY4pQf5PEF4PSLA.f8078c7bb548cacf44639c41c40ce50af5f88287ab56d7eab2e15aec1d1221a7";

const myEncoded = encryptReserveSlotCaptcha(raw, RESERVE_SLOT_KEY, RESERVE_SLOT_PREFIX_LEN, RESERVE_SLOT_ENCODE_LEN);

console.log('Match?', myEncoded === expectedEncoded);
console.log('raw:', raw.slice(0, 30));
console.log('expected:', expectedEncoded.slice(0, 30));
console.log('actual:  ', myEncoded.slice(0, 30));
