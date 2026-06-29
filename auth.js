import fs from 'fs';

const CRED_DIR   = '/etc/nginx/njs';
const LOGIN_FILE = '/etc/nginx/njs/login.html';
const RP_NAME    = 'njs-auth';
const RP_ID      = '';
const ORIGIN     = '';
const SESSION_TTL          = 86400;
const SESSION_MAX_LIFETIME = 604800;
const CHALLENGE_TTL        = 300;
const COOKIE               = 'njs_session';
const MAX_BODY             = 16384;

const nowSec = () => Math.floor(Date.now() / 1000);

const b64urlDecode = (s) => {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return new Uint8Array(Buffer.from(s, 'base64'));
};

const b64urlEncode = (bytes) =>
    Buffer.from(bytes).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const randomB64 = (n) => {
    const buf = new Uint8Array(n);
    crypto.getRandomValues(buf);
    return b64urlEncode(buf);
};

const concat = (a, b) => {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
};

const constantEqual = (a, b) => {
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
};

const sha256 = (data) => crypto.subtle.digest('SHA-256', data);

const rpId = (r) => {
    if (RP_ID) return RP_ID;
    return r.variables?.host ? r.variables.host.split(':')[0] : 'localhost';
};

const origin = (r) => {
    if (ORIGIN) return ORIGIN;
    const scheme = r.variables?.scheme ?? 'https';
    const host = r.variables?.http_host ?? rpId(r);
    return `${scheme}://${host}`;
};

const getCookie = (r, name) => {
    const h = r.headersIn['Cookie'];
    if (!h) return null;
    const prefix = `${name}=`;
    for (const part of h.split(';')) {
        const kv = part.trim();
        if (kv.slice(0, prefix.length) === prefix) return kv.slice(prefix.length);
    }
    return null;
};

const json = (r, code, obj) => {
    r.headersOut['Content-Type'] = 'application/json; charset=utf-8';
    r.return(code, JSON.stringify(obj));
};

const credFile = (r) => {
    const id = rpId(r);
    if (/[^a-zA-Z0-9.\-:]/.test(id)) throw new Error('bad rpId');
    return `${CRED_DIR}/${id}.json`;
};

const loadCred = (r) => {
    try {
        return JSON.parse(fs.readFileSync(credFile(r), 'utf8'));
    } catch (e) {
        return null;
    }
};

const sessionCookie = (sid, maxAge) =>
    `${COOKIE}=${sid}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;

const addCookie = (r, cookie) => {
    const current = r.headersOut['Set-Cookie'];
    if (!current) {
        r.headersOut['Set-Cookie'] = cookie;
        return;
    }
    r.headersOut['Set-Cookie'] = Array.isArray(current) ? current.concat(cookie) : [current, cookie];
};

const createSession = (r) => {
    const sid = randomB64(32);
    const now = nowSec();
    const exp = now + SESSION_TTL;
    ngx.shared.authsess.set(sid, `${now}|${exp}`);
    r.headersOut['Set-Cookie'] = sessionCookie(sid, SESSION_TTL);
};

const sessionInfo = (r) => {
    const sid = getCookie(r, COOKIE);
    if (!sid) return null;
    const raw = ngx.shared.authsess.get(sid);
    if (!raw) return null;
    const now = nowSec();
    const parts = raw.split('|');
    const createdAt = parseInt(parts[0], 10);
    const exp = parseInt(parts[1], 10);
    if (Number.isNaN(createdAt) || Number.isNaN(exp)) {
        ngx.shared.authsess.delete(sid);
        return null;
    }
    const maxExp = createdAt + SESSION_MAX_LIFETIME;
    if (now >= maxExp) {
        ngx.shared.authsess.delete(sid);
        return null;
    }
    if (exp < now) {
        ngx.shared.authsess.delete(sid);
        return null;
    }
    return { sid, now, createdAt, maxExp };
};

const validSession = (r) => !!sessionInfo(r);

const refreshSession = (r) => {
    const s = sessionInfo(r);
    if (!s) return false;
    const nextExp = Math.min(s.now + SESSION_TTL, s.maxExp);
    ngx.shared.authsess.set(s.sid, `${s.createdAt}|${nextExp}`);
    addCookie(r, sessionCookie(s.sid, nextExp - s.now));
    return true;
};

const alreadyRegistered = (r) => {
    if (!loadCred(r)) return false;
    json(r, 403, { error: 'already registered' });
    return true;
};

const loadRegisteredCred = (r) => {
    const cred = loadCred(r);
    if (!cred) json(r, 404, { error: 'not registered' });
    return cred;
};

const clearChallenge = (r) => {
    const key = getCookie(r, 'njs_chal');
    if (!key) return;
    ngx.shared.authchal.delete(key);
    ngx.shared.authchal.delete(`${key}:taken`);
};

const requirePostSameOrigin = (r) => {
    if (r.method !== 'POST') {
        json(r, 405, { error: 'POST only' });
        return false;
    }
    const ref = r.headersIn['Origin'];
    if (!ref || ref !== origin(r)) {
        json(r, 403, { error: 'forbidden' });
        return false;
    }
    return true;
};

const setChallenge = (r, type, challenge) => {
    const key = randomB64(16);
    ngx.shared.authchal.set(key, `${type}|${challenge}|${nowSec() + CHALLENGE_TTL}`);
    r.headersOut['Set-Cookie'] =
        `njs_chal=${key}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${CHALLENGE_TTL}`;
};

const takeChallenge = (r, type) => {
    const key = getCookie(r, 'njs_chal');
    if (!key) return null;
    const raw = ngx.shared.authchal.get(key);
    if (!raw) return null;
    const parts = raw.split('|');
    if (parts[0] !== type) return null;
    if (parseInt(parts[2], 10) < nowSec()) return null;
    if (!ngx.shared.authchal.add(`${key}:taken`, '1', CHALLENGE_TTL * 1000)) return null;
    return parts[1];
};

const CBOR_MAX_DEPTH = 16;
const CBOR_MAX_BYTES = 65536;
const CBOR_MAX_TEXT  = 65536;

class CborReader {
    constructor(bytes) {
        this.b = bytes;
        this.p = 0;
        this.len = bytes.length;
        this.depth = 0;
    }

    check(n) {
        if (this.p + n > this.len) throw new Error('cbor overflow');
    }

    u8() {
        this.check(1);
        return this.b[this.p++];
    }

    readUint(info) {
        if (info < 24) return info;
        if (info === 24) return this.u8();
        if (info === 25) {
            this.check(2);
            return (this.u8() << 8) | this.u8();
        }
        if (info === 26) {
            this.check(4);
            return (this.u8() * 16777216) + (this.u8() << 16) + (this.u8() << 8) + this.u8();
        }
        if (info === 27) {
            this.check(8);
            const hi = (this.u8() * 16777216) + (this.u8() << 16) + (this.u8() << 8) + this.u8();
            const lo = (this.u8() * 16777216) + (this.u8() << 16) + (this.u8() << 8) + this.u8();
            return hi * 4294967296 + lo;
        }
        throw new Error('cbor bad info');
    }

    decode() {
        if (this.depth > CBOR_MAX_DEPTH) throw new Error('cbor depth');
        const ib = this.u8();
        const major = ib >> 5;
        const info = ib & 0x1f;
        let len, bytes, str;
        switch (major) {
            case 0:
                return this.readUint(info);
            case 1:
                return -1 - this.readUint(info);
            case 2:
                len = this.readUint(info);
                if (len > CBOR_MAX_BYTES) throw new Error('cbor bytes too long');
                this.check(len);
                bytes = this.b.subarray(this.p, this.p + len);
                this.p += len;
                return bytes;
            case 3:
                len = this.readUint(info);
                if (len > CBOR_MAX_TEXT) throw new Error('cbor text too long');
                this.check(len);
                str = Buffer.from(this.b.subarray(this.p, this.p + len)).toString('utf8');
                this.p += len;
                return str;
            case 4: {
                len = this.readUint(info);
                const arr = [];
                this.depth++;
                for (let i = 0; i < len; i++) arr.push(this.decode());
                this.depth--;
                return arr;
            }
            case 5: {
                len = this.readUint(info);
                const obj = {};
                this.depth++;
                for (let i = 0; i < len; i++) {
                    const key = this.decode();
                    obj[key] = this.decode();
                }
                this.depth--;
                return obj;
            }
            case 7:
                if (info === 20) return false;
                if (info === 21) return true;
                return null;
            default:
                throw new Error('cbor major');
        }
    }
}

const cborDecodeFirst = (bytes) => {
    const rd = new CborReader(bytes);
    return { value: rd.decode(), end: rd.p };
};

const parseAuthData = (ad) => {
    if (ad.length < 37) throw new Error('authData too short');
    const result = {
        rpIdHash: ad.subarray(0, 32),
        flags: ad[32],
        up: !!(ad[32] & 0x01),
        uv: !!(ad[32] & 0x04),
        at: !!(ad[32] & 0x40),
        signCount: ((ad[33] << 24) | (ad[34] << 16) | (ad[35] << 8) | ad[36]) >>> 0
    };
    if (result.at) {
        if (ad.length < 55) throw new Error('authData too short for attested cred');
        let off = 37;
        result.aaguid = ad.subarray(off, off + 16); off += 16;
        const credIdLen = (ad[off] << 8) | ad[off + 1]; off += 2;
        if (off + credIdLen > ad.length) throw new Error('credId overflows authData');
        result.credId = ad.subarray(off, off + credIdLen); off += credIdLen;
        if (off >= ad.length) throw new Error('no COSE key in authData');
        result.cosePub = cborDecodeFirst(ad.subarray(off)).value;
    }
    return result;
};

const coseToRawP256 = (cose) => {
    if (cose[1] !== 2) throw new Error('bad cose key');
    if (cose[-1] !== 1) throw new Error('bad cose key');
    if (cose[3] !== -7) throw new Error('bad cose key');
    const x = cose[-2];
    const y = cose[-3];
    if (!x || !y || x.length !== 32 || y.length !== 32) throw new Error('bad cose key');
    const raw = new Uint8Array(65);
    raw[0] = 0x04;
    raw.set(x, 1);
    raw.set(y, 33);
    return raw;
};

const derToRaw = (der) => {
    if (der.length < 8) throw new Error('der too short');
    let p = 0;
    if (der[p++] !== 0x30) throw new Error('bad der');
    let seqLen = der[p++];
    if (seqLen & 0x80) {
        const nb = seqLen & 0x7f;
        if (nb === 0 || nb > 4 || p + nb > der.length) throw new Error('bad der len');
        seqLen = 0;
        for (let i = 0; i < nb; i++) seqLen = (seqLen << 8) | der[p++];
    }
    if (p + seqLen !== der.length) throw new Error('bad der seq len');
    if (p >= der.length || der[p++] !== 0x02) throw new Error('bad der r');
    const rlen = der[p++];
    if (p + rlen > der.length) throw new Error('der r overflow');
    const rb = der.subarray(p, p + rlen); p += rlen;
    if (der[p++] !== 0x02) throw new Error('bad der s');
    const slen = der[p++];
    if (p + slen > der.length) throw new Error('der s overflow');
    const sb = der.subarray(p, p + slen);
    const pad32 = (v) => {
        if (v.length > 32) {
            if (v.length !== 33 || v[0] !== 0x00) throw new Error('bad der');
            v = v.subarray(1);
        }
        const out = new Uint8Array(32);
        out.set(v, 32 - v.length);
        return out;
    };
    return concat(pad32(rb), pad32(sb));
};

const verifyClientData = (clientDataJSON, type, expectedChallenge, r) => {
    const cd = JSON.parse(Buffer.from(clientDataJSON).toString('utf8'));
    const expectedOrigin = origin(r);
    if (cd.type !== type) throw new Error(`clientData type mismatch: expected ${type}, got ${cd.type}`);
    if (cd.challenge !== expectedChallenge) throw new Error('challenge mismatch');
    if (cd.origin !== expectedOrigin) throw new Error(`origin mismatch: expected ${expectedOrigin}, got ${cd.origin}`);
    return cd;
};

const loginUrl = (r) => {
    const uri = r.variables?.request_uri ?? r.uri ?? '/';
    const next = uri[0] === '/' && uri.slice(0, 2) !== '//' ? uri : '/';
    return `/auth/login?next=${encodeURIComponent(next)}`;
};

const access = (r) => {
    if (validSession(r)) return;
    r.return(302, loginUrl(r));
};

const refresh = (r) => {
    refreshSession(r);
};

const state = (r) => {
    json(r, 200, {
        registered: !!loadCred(r),
        authenticated: validSession(r)
    });
};

const logout = (r) => {
    if (!requirePostSameOrigin(r)) return;
    const sid = getCookie(r, COOKIE);
    if (sid) ngx.shared.authsess.delete(sid);
    clearChallenge(r);
    r.headersOut['Set-Cookie'] = [
        `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
        'njs_chal=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0'
    ];
    json(r, 200, { ok: true });
};

const registerBegin = (r) => {
    if (!requirePostSameOrigin(r)) return;
    if (alreadyRegistered(r)) return;
    clearChallenge(r);
    const challenge = randomB64(32);
    setChallenge(r, 'reg', challenge);
    json(r, 200, {
        rp: { name: RP_NAME, id: rpId(r) },
        user: { id: b64urlEncode(new Uint8Array([1, 2, 3, 4])), name: 'admin', displayName: 'Administrator' },
        challenge,
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        authenticatorSelection: { userVerification: 'preferred', residentKey: 'preferred' },
        timeout: 60000,
        attestation: 'none'
    });
};

const parseBodyAndChallenge = (r, type) => {
    if (!r.requestText || r.requestText.length > MAX_BODY) {
        json(r, 413, { error: 'payload too large' });
        return null;
    }
    let body;
    try {
        body = JSON.parse(r.requestText);
    } catch (e) {
        json(r, 400, { error: 'invalid JSON body' });
        return null;
    }
    const expected = takeChallenge(r, type);
    if (!expected) {
        json(r, 400, { error: 'missing or expired challenge' });
        return null;
    }
    return { body, expected };
};

const registerFinish = async (r) => {
    if (!requirePostSameOrigin(r)) return;
    if (alreadyRegistered(r)) return;

    const parsed = parseBodyAndChallenge(r, 'reg');
    if (!parsed) return;
    const { body, expected } = parsed;

    try {
        const clientDataJSON = b64urlDecode(body.response.clientDataJSON);
        verifyClientData(clientDataJSON, 'webauthn.create', expected, r);

        const attObj = cborDecodeFirst(b64urlDecode(body.response.attestationObject)).value;
        const authData = parseAuthData(attObj.authData);

        if (!authData.up) throw new Error('user not present');
        if (body.id !== b64urlEncode(authData.credId)) throw new Error('credential id mismatch');
        if (!authData.at) throw new Error('missing attested credential data');
        if (attObj.fmt !== 'none') throw new Error('attestation format not none');

        const h = await sha256(Buffer.from(rpId(r)));
        if (!constantEqual(new Uint8Array(h), authData.rpIdHash)) throw new Error('rpId hash mismatch');

        const cred = {
            credId: b64urlEncode(authData.credId),
            publicKey: b64urlEncode(coseToRawP256(authData.cosePub)),
            signCount: authData.signCount,
            createdAt: nowSec()
        };
        json(r, 200, { ok: true, file: credFile(r), credential: cred });
    } catch (e) {
        json(r, 400, { error: e.message || 'bad request' });
    }
};

const loginBegin = (r) => {
    if (!requirePostSameOrigin(r)) return;
    const cred = loadRegisteredCred(r);
    if (!cred) return;
    clearChallenge(r);
    const challenge = randomB64(32);
    setChallenge(r, 'login', challenge);
    json(r, 200, {
        challenge,
        timeout: 60000,
        rpId: rpId(r),
        allowCredentials: [{ type: 'public-key', id: cred.credId }],
        userVerification: 'preferred'
    });
};

const loginFinish = async (r) => {
    if (!requirePostSameOrigin(r)) return;
    const cred = loadRegisteredCred(r);
    if (!cred) return;

    const req = parseBodyAndChallenge(r, 'login');
    if (!req) return;
    const { body, expected } = req;

    try {
        if (body.id !== cred.credId) throw new Error('credential id mismatch');

        const clientDataJSON = b64urlDecode(body.response.clientDataJSON);
        verifyClientData(clientDataJSON, 'webauthn.get', expected, r);

        const authData = b64urlDecode(body.response.authenticatorData);
        const parsed = parseAuthData(authData);
        if (!parsed.up) throw new Error('user not present');

        const sig = derToRaw(b64urlDecode(body.response.signature));
        const pubRaw = b64urlDecode(cred.publicKey);

        const [rpHash, cdHash] = await Promise.all([
            sha256(Buffer.from(rpId(r))),
            sha256(clientDataJSON)
        ]);
        if (!constantEqual(new Uint8Array(rpHash), parsed.rpIdHash)) throw new Error('rpId hash mismatch');

        const signedData = concat(authData, new Uint8Array(cdHash));
        const key = await crypto.subtle.importKey(
            'raw', pubRaw,
            { name: 'ECDSA', namedCurve: 'P-256' },
            false, ['verify']
        );
        const ok = await crypto.subtle.verify(
            { name: 'ECDSA', hash: 'SHA-256' },
            key, sig, signedData
        );

        if (!ok) throw new Error('signature verification failed');
        if (cred.signCount > 0 && parsed.signCount !== 0 &&
            parsed.signCount <= cred.signCount) {
            throw new Error('sign count not increasing');
        }
        createSession(r);
        json(r, 200, { ok: true });
    } catch (e) {
        json(r, 401, { error: e.message || 'bad request' });
    }
};

const serveLogin = (r) => {
    let html;
    try {
        html = fs.readFileSync(LOGIN_FILE, 'utf8');
    } catch (e) {
        r.return(500, 'login.html not found');
        return;
    }
    r.headersOut['Content-Type'] = 'text/html; charset=utf-8';
    r.return(200, html);
};

const route = (r) => {
    const uri = r.uri;
    if (uri === '/auth/login')           return serveLogin(r);
    if (uri === '/auth/state')           return state(r);
    if (uri === '/auth/logout')          return logout(r);
    if (uri === '/auth/register/begin')  return registerBegin(r);
    if (uri === '/auth/register/finish') return registerFinish(r);
    if (uri === '/auth/login/begin')     return loginBegin(r);
    if (uri === '/auth/login/finish')    return loginFinish(r);
    json(r, 404, { error: 'not found' });
};

export default { route, access, refresh };
