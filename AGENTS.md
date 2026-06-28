# AGENTS.md

Guidance for AI coding agents working on the `auth/` njs WebAuthn module.

## Overview

Single-user WebAuthn / Passkey authentication middleware for nginx, gating any backend via `auth_request`. Zero dependencies — pure njs (QuickJS engine) with a built-in CBOR decoder, COSE key parser, DER signature converter, and WebCrypto ES256 verification.

| File | Purpose |
|------|---------|
| `auth.js` | Core module: route dispatcher, CBOR/COSE/DER, WebAuthn verify, sessions |
| `login.html` | Login / registration page (auto-detects state) |
| `nginx.conf` | Example config (whole-site and per-location modes) |
| `README.md` / `README_en.md` | Chinese / English docs, kept in sync |
	
## Runtime constraints

- Target is **njs running the QuickJS engine** (`js_engine qjs;`), njs ≥ 1.0.0 recommended (min ≥ 0.8.10). This is **not** Node.js or a browser.
- Use ES modules only: `import` / `export default`. **Never** use `require()` — it breaks the shared VM.
- All `js_import` modules under QuickJS **share one VM**. A single module that fails to load makes every module's functions report as "not found".
- Available built-ins: `Buffer`, `fs`, `crypto`/`crypto.subtle` (WebCrypto), `ngx.shared.*` dict zones (`authsess`, `authchal`), and the `r` (request) object. No npm packages.
- `auth.js` runs in njs. `login.html` is a browser page.

## Conventions

- 4-space indent, `const` arrow functions, terse single-purpose helpers.
- No code comments unless explicitly requested.
- Configuration lives in `const` declarations at the top of `auth.js`. Keep the README config tables in sync with these constants.
- Security-sensitive code — preserve:
  - constant-time comparison for `rpIdHash`
  - one-time, type-bound (reg/login) challenges with the `:taken` replay marker
  - CBOR/authData/COSE/DER bounds & length checks
  - cookie flags `HttpOnly; Secure; SameSite=Strict`
  - session sliding expiry plus the `SESSION_MAX_LIFETIME` absolute cap
  - `next` param validation (relative paths only)

## Documentation

- When changing behavior or config constants, update **both** `README.md` and `README_en.md` so they stay in sync.

## Validating

No test suite or build step. To sanity-check:

- Verify nginx loads the module and config: `nginx -t` with `js_import auth from auth.js;`.
- Manual flow: visit `/auth/login` (register mode) → save the returned `<rpId>.json` → reload (login mode) → log in.

## Git

- Do not commit unless explicitly asked.
- Never commit credential files (`<rpId>.json`) or secrets.
