# Dashboard authentication modes

ThreatLens supports two modes selected with `THREATLENS_AUTH_MODE`.

- `local` is the default. It does not require dashboard account setup and
  restricts dashboard API requests to loopback clients. Keep the backend bound
  to `127.0.0.1` and do not expose this mode to an untrusted network.
- `demo` enables one configured shared username and password hash. It uses
  in-memory server-side sessions, secure cookies, HTTPS-origin validation,
  CSRF checks for mutation requests, and login rate limits. It is a demo gate,
  not individual analyst accounts or full role-based authorization. Session and
  rate-limit state are process-local and are not shared across workers.

Demo mode requires the exact HTTPS frontend origin in
`THREATLENS_CORS_ORIGINS`. The browser must send the session cookie and
`X-CSRF-Token` on state-changing requests. Generate the password hash locally
with `python -m scripts.hash_demo_password`; do not configure plaintext
passwords. Hosted use additionally requires HTTPS, PostgreSQL, and a fresh
empty database initialized using the documented Alembic baseline. PostgreSQL
runtime compatibility and deployment security review remain outstanding.

The application is a single-organization prototype without tenant isolation
and is not production-ready for unrestricted public exposure.

Windows collector source credentials are separate. They are created and
managed in **Administration**, stored as hashes, and required by the Windows
event receiver.
