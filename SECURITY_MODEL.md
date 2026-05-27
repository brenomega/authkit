# AuthKit Security Model

## Roles

- `ADMIN`: global platform administrator. Can view and manage all tenants, users, and OAuth clients. Production deployments must require current-password step-up plus TOTP MFA or a fresh passkey-authenticated session for every admin write.
- `TENANT_ADMIN`: tenant-scoped administrator. Can view users and OAuth clients only inside its own `tenant_id`. Cannot create, update, demote, promote, or disable global admins or other tenant administrators. Cannot manage global OAuth clients.
- `OWNER`: tenant owner identity for future product-level ownership flows. It has normal self-service account access in the current API and is not admitted to the admin plane.
- `USER`: standard self-service identity. Can access only `/api/v1/users/me/**` resources tied to its own JWT subject and tenant.

## Object Authorization

Hibernate tenant filtering is defense-in-depth only. Service methods that load objects by direct identifiers must enforce object-level authorization before returning or mutating data. AuthKit uses `404`-style not-found failures for cross-tenant self-service access and access-denied failures for explicit admin-plane policy violations.

## Session Revocation

AuthKit access JWTs are bound to the refresh-session `jti`. Authenticated requests are accepted only while that `jti` remains present in the server-side token store. Logout, logout-all, password reset, account deletion, session revocation, role changes, and refresh-token family compromise therefore deny affected access tokens before their natural expiry.
