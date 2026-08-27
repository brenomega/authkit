# First-party same-site browser example

Serve this directory from the exact HTTPS origin configured in AuthKit CORS and frontend URLs. Set `window.AUTHKIT_URL` before `app.js`, or replace the development placeholder. The example exercises credentialed login, an HttpOnly refresh cookie, double-submit CSRF, memory-only access tokens, profile, rotation, logout, and fragment removal. It intentionally provides no production UI, error copy, analytics, storage abstraction, or branding.

For a local-only inspection, run an HTTPS static server approved by your environment. Plain HTTP is permitted only for loopback development and is not golden-path evidence.
