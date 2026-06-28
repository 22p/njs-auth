# njs WebAuthn

Single-user WebAuthn / Passkey authentication middleware for nginx njs.

Zero dependencies — pure njs (QuickJS engine) with built-in CBOR decoder, COSE key parser, DER signature converter, and WebCrypto ECDSA verification.

## Files

| File | Purpose |
|------|---------|
| `auth.js` | Core module: route dispatcher, CBOR, COSE, DER, WebAuthn verify, sessions |
| `login.html` | Login / registration page |
| `nginx.conf` | Example config (whole-site and per-location modes) |

## Requirements

- nginx with `ngx_http_js_module` (njs module)
- njs ≥ 1.0.0 recommended, running the **QuickJS engine** (`js_engine qjs;`). Minimum ≥ 0.8.10 (QuickJS gained `Buffer`/`fs`/WebCrypto across 0.8.6–0.8.10).

## Setup

### 1. Place files

Put `auth.js` and `login.html` in the same directory (default `/etc/nginx/njs/`).

### 2. http block

```nginx
http {
    js_engine qjs;
    js_path "/etc/nginx/njs/";
    js_import auth from auth.js;

    js_shared_dict_zone zone=authsess:1m timeout=86400s;
    js_shared_dict_zone zone=authchal:1m timeout=300s;

    # ... server blocks
}
```

### 3. Auth endpoints (required for both modes)

```nginx
location ^~ /auth/ {
    auth_request off;
    client_max_body_size 16k;
    js_content auth.route;
}
location = /auth/verify {
    internal;
    auth_request off;
    error_page 401 403 = @verify_pass;   # required for whole-site mode
    js_content auth.verify;
}
location @verify_pass   { return 401; }
location @auth_redirect { return 302 /auth/login?next=$request_uri; }
```

### 4. Choose protection mode

**Mode A — whole site:**

```nginx
server {
    auth_request /auth/verify;
    error_page 401 403 = @auth_redirect;

    # ... auth endpoints from step 3 ...
    # ... your locations ...
}
```

To exempt a path, add `auth_request off;` inside its location.

**Mode B — per location:**

```nginx
server {
    # ... auth endpoints from step 3 (no @verify_pass needed) ...

    location /protected/ {
        auth_request /auth/verify;
        error_page 401 403 = @auth_redirect;
    }

    location / {
        # public, no auth
    }
}
```

## First use

1. Visit `/auth/login` — page shows "register" mode (no credential file yet).
2. Complete biometric / passkey registration.
3. Copy the displayed JSON, save as `<rpId>.json` in the credential directory:

```sh
vi /etc/nginx/njs/example.com.json
chmod 644 /etc/nginx/njs/example.com.json
```

4. Reload — page shows "login" mode. Log in with your passkey.

The credential file is **read-only** by nginx — no write permissions needed. Each site gets its own file named after its RP ID, so multiple sites can share the same `auth.js`.

## Endpoints

All served by `auth.route` via `location ^~ /auth/`.

| Path | Method | Description |
|------|--------|-------------|
| `/auth/login` | GET | Login / registration page |
| `/auth/state` | GET | `{registered, authenticated}` |
| `/auth/register/begin` | POST | Get registration options |
| `/auth/register/finish` | POST | Submit credential, returns JSON to save |
| `/auth/login/begin` | POST | Get login challenge |
| `/auth/login/finish` | POST | Submit assertion, creates session |
| `/auth/logout` | POST | Destroy session |
| `/auth/verify` | internal | For `auth_request`, returns 204 or 401 |

## Configuration

In `auth.js`:

| Constant | Default | Description |
|----------|---------|-------------|
| `CRED_DIR` | `/etc/nginx/njs` | Credential directory (files named `<rpId>.json`) |
| `LOGIN_FILE` | `/etc/nginx/njs/login.html` | Login page path |
| `RP_NAME` | `njs-auth` | Relying Party name |
| `RP_ID` | `""` | Relying Party ID (auto-detected from `$host` if empty) |
| `ORIGIN` | `""` | Expected origin (auto-derived from `$scheme` + `$http_host` if empty) |
| `SESSION_TTL` | `86400` | Session sliding lifetime, refreshed on each valid request (seconds) |
| `SESSION_MAX_LIFETIME` | `604800` | Absolute session cap; session is destroyed this long after creation regardless of activity (seconds) |
| `CHALLENGE_TTL` | `300` | Challenge lifetime (seconds) |
| `COOKIE` | `njs_session` | Session cookie name |
| `MAX_BODY` | `16384` | Max request body size for finish endpoints; larger returns 413 (bytes) |

`RP_ID` is normally left empty — it auto-detects from nginx's `$host`, which reflects the actually requested domain. Note `$host` falls back to the client `Host` header when no `server_name` matches, so you should run a `default_server` that rejects unknown hosts. Set `RP_ID` explicitly only when the RP ID differs from the server name:

```js
const RP_ID = 'auth.example.com';
```

Origin is auto-derived as `$scheme://$http_host`. Override with `ORIGIN`:

```js
const ORIGIN = 'https://auth.example.com:8443';
```

## Security

- All cookies: `HttpOnly; Secure; SameSite=Strict`
- Challenges: one-time, type-bound (reg vs login), replay-protected via a `:taken` marker (original entry expires by TTL)
- Registration: a stale challenge cookie is rotated (old challenge invalidated, new one issued) on each `register/begin`; an existing credential file blocks re-registration
- CBOR decoder: depth limit (16), byte/text length limits (64KB), bounds checks
- authData parser: length validation, overflow checks
- COSE key: kty (EC2), crv (P-256), alg (ES256), and coordinate length validation
- DER parser: length validation, overflow checks
- Constant-time comparison for rpIdHash
- Error messages: returned to the client for diagnostics; sensitive internal state (file paths, key material) is not exposed
- Logout: POST-only (CSRF protected)
- Session: sliding expiry (TTL refreshed on each valid request) with an absolute `SESSION_MAX_LIFETIME` cap
- Login page `next` param validation (relative paths only, rejects `//evil.com`)
- RP ID / Origin: derived from nginx server variables (`$host`, `$scheme`, `$http_host`); reflect the requested domain to support multi-domain use; run a `default_server` to reject unknown hosts. Can be overridden via `RP_ID` / `ORIGIN` constants

## Notes

- **HTTPS required** — WebAuthn only works in secure contexts (except `localhost`).
- Only **ES256 (alg -7)** and **`none` attestation** are supported — covers all major platform authenticators (Touch ID, Windows Hello, mobile passkeys, security keys, etc.).
- `signCount` is not written back; security is sufficient for single-user self-hosted scenarios.
- To reset / re-register: delete the corresponding `<rpId>.json` file.
- Single user only — one credential file, suitable for personal services / admin panel protection.
