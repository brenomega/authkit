# First-party same-site browser example

Serve this directory from the exact HTTPS origin configured in AuthKit CORS and frontend URLs. Set `window.AUTHKIT_URL` before `app.js`, or replace the development placeholder. The executable controls cover registration, confirmation/resend, password login, refresh rotation, profile, logout, password recovery/reset, TOTP enrollment/confirmation, passkey registration and passkey login. Access tokens and email-action tokens stay memory-only; refresh uses the HttpOnly cookie plus double-submit CSRF. Email fragments are removed before the operator chooses the confirmation or recovery action. Backup codes and TOTP secrets are deliberately redacted from the generic output because production UI must give them a dedicated one-time display ceremony.

Use a WebAuthn-capable current browser. Its native `PublicKeyCredential.toJSON()` serialization is required; the example fails closed instead of inventing a lossy credential conversion on older browsers. The password field is reused as the proposed new password during reset. This sample intentionally provides no production UI, error copy, analytics, storage abstraction, or branding.

For a local-only inspection, run an HTTPS static server approved by your environment. Plain HTTP is permitted only for loopback development and is not golden-path evidence.
