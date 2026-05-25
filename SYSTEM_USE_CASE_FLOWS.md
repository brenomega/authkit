# AuthKit Current-State Use Case Flows

This document diagrams the controller-layer endpoints currently implemented in AuthKit and the infrastructure each flow depends on. Diagrams use Mermaid sequence syntax so they can be rendered by GitHub, IDE plugins, or documentation tooling.

Source surface reviewed:

- `AuthController`: `/api/v1/auth/**`
- `UserController`: `/api/v1/users/me/**`
- `JwksController`: `/.well-known/jwks.json`
- Shared infrastructure: Kubernetes manifests, Spring Security filter chain, network/rate-limit filters, Redis token storage, Caffeine authority/rate-limit caches, PostgreSQL/Flyway schema, RabbitMQ email queue, Resend email provider, durable security/consent audit events, Prometheus metrics.

## Shared Infrastructure Path

Current request order in the codebase is:

1. External client reaches the edge reverse proxy or ingress controller.
2. Kubernetes `NetworkPolicy` only permits ingress-controller traffic to the AuthKit pods.
3. `OriginFirewallFilter` rejects direct backend access unless the remote source is trusted.
4. `RateLimitingFilter` resolves the real client IP, applies local Caffeine rate limiting first, then distributed Redis Bucket4j rate limiting.
5. `RequestBodySizeLimitFilter` rejects oversized POST/PUT/PATCH bodies before JSON parsing or password hashing.
6. Spring OAuth2 resource-server JWT validation runs for authenticated routes.
7. `WorkerAuthFilter` applies only to `/api/v1/internal/**`; no controller endpoint for that prefix currently exists in this repository.
8. `UserAuthoritiesFilter` refreshes authorities from a local Caffeine cache; on cache miss it loads the current user snapshot from PostgreSQL.
9. Controller/service logic executes.
10. Durable security events are written through a bounded async writer, with synchronous fallback when configured.
11. Metrics are exposed at `/actuator/prometheus`; alerts are defined in `k8s/06-prometheus-rules.yaml`.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant RP as Reverse Proxy / Ingress
    participant NP as K8s NetworkPolicy
    participant OF as OriginFirewallFilter
    participant RL as RateLimitingFilter
    participant LC as Caffeine rate bucket
    participant RR as Redis rate bucket
    participant BL as RequestBodySizeLimitFilter
    participant JWT as Bearer JWT Decoder
    participant WF as WorkerAuthFilter
    participant AF as UserAuthoritiesFilter
    participant AC as Caffeine authority cache
    participant DB as PostgreSQL
    participant CT as Controller

    C->>RP: HTTPS request
    RP->>NP: Forward to authkit-service:8080
    alt Source is not ingress controller / trusted source
        NP-->>RP: Drop or deny by policy
        RP-->>C: Connection denied
    else Source accepted
        NP->>OF: Deliver request to pod
        OF->>OF: Check remoteAddr against trusted origins
        alt Untrusted origin
            OF-->>C: 403 Invalid Origin
        else Trusted origin
            OF->>RL: Continue
            RL->>LC: Consume local IP bucket
            alt Local bucket exhausted
                RL-->>C: 429 Too Many Requests
            else Local allowed
                RL->>RR: Consume distributed IP bucket
                alt Redis bucket exhausted
                    RL-->>C: 429 Too Many Requests
                else Redis unavailable
                    RL->>RL: Record infrastructure failure, fail open to local limit
                    RL->>BL: Continue
                else Redis allowed
                    RL->>BL: Continue
                end
            end
            BL->>BL: Check Content-Length and streamed body size
            alt Body too large
                BL-->>C: 413 Request body too large
            else Body accepted
                BL->>JWT: Continue
                alt Public endpoint
                    JWT->>CT: Skip auth requirement
                else Bearer token missing/invalid/expired
                    JWT-->>C: 401 Unauthorized
                else Bearer token valid
                    JWT->>WF: Continue
                    WF->>AF: Continue
                    AF->>AC: Lookup current user authorities
                    alt Authority cache hit
                        AC-->>AF: Current authorities and enabled flag
                    else Cache miss
                        AF->>DB: findById(jwt.sub)
                        DB-->>AF: User snapshot
                        AF->>AC: Cache snapshot
                    end
                    alt User absent or disabled/deleted
                        AF-->>C: 401 Unauthorized
                    else Current authorities applied
                        AF->>CT: Continue to controller
                    end
                end
            end
        end
    end
```

## Endpoint Summary

| Endpoint | Auth | Primary state | Key infrastructure |
|---|---:|---|---|
| `POST /api/v1/auth/login` | Public | PostgreSQL user, Redis refresh token | Caffeine/Redis rate limits, Argon2 limiter, lockout Caffeine/Redis, audit DB |
| `POST /api/v1/auth/refresh` | Refresh cookie + CSRF | Redis refresh token family | CSRF double-submit cookie, Redis Lua rotation, audit DB |
| `POST /api/v1/auth/logout` | Refresh cookie + CSRF | Redis refresh token session | CSRF double-submit cookie, Redis revocation, audit DB |
| `POST /api/v1/auth/logout-all` | Bearer JWT | Redis all sessions | JWT validation, authority cache, Redis revocation |
| `POST /api/v1/auth/register` | Public | PostgreSQL user, email outbox | Argon2, consent event DB, outbox, RabbitMQ, Resend |
| `POST /api/v1/auth/email-confirmation/confirm` | Public | PostgreSQL user token hash | Audit DB |
| `POST /api/v1/auth/password-recovery/request` | Public | Redis recovery token, email outbox | Stealth response, outbox, RabbitMQ, Resend, audit DB |
| `POST /api/v1/auth/password-recovery/reset` | Public | Redis recovery token, PostgreSQL password | Argon2 limiter, Redis session revoke, outbox, audit DB |
| `GET /api/v1/users/me` | Bearer JWT | PostgreSQL user | Authority Caffeine/DB cache, tenant check |
| `GET /api/v1/users/me/consent` | Bearer JWT | PostgreSQL user | Authority Caffeine/DB cache, tenant check |
| `POST /api/v1/users/me/export` | Bearer JWT + password step-up | PostgreSQL user, consent events, security events | Argon2 limiter, audit DB |
| `PATCH /api/v1/users/me` | Bearer JWT | PostgreSQL user | Authority Caffeine/DB cache, tenant check |
| `POST /api/v1/users/me/password` | Bearer JWT + current password | PostgreSQL password, Redis sessions | Argon2 limiter, lockout check, audit DB |
| `GET /api/v1/users/me/sessions` | Bearer JWT | Redis refresh sessions | Authority Caffeine/DB cache |
| `DELETE /api/v1/users/me/sessions/{jti}` | Bearer JWT | Redis refresh session | Lockout check, audit DB |
| `DELETE /api/v1/users/me` | Bearer JWT + password step-up | PostgreSQL anonymized user, Redis sessions | Argon2 limiter, authority cache eviction, audit DB |
| `GET /.well-known/jwks.json` | Public | RSA public key config | Downstream stateless JWT verification |

## 1. Login

`POST /api/v1/auth/login`

Infrastructure role: edge and Kubernetes restrict entry; network filters rate-limit before hashing; `AccountLockoutService` uses Redis as the global lockout source when available and Caffeine as local fallback; Argon2 verification is bounded by `Argon2ConcurrencyLimiter`; refresh state is stored in Redis; access tokens are stateless JWTs; refresh and CSRF tokens are returned as cookies; security events and Prometheus counters are emitted.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant I as Shared ingress filters
    participant AC as AuthController
    participant AS as AuthService
    participant LS as AccountLockoutService
    participant LK as Redis/Caffeine lockout
    participant DB as PostgreSQL users
    participant ARG as Argon2 limiter + PasswordEncoder
    participant TS as RedisTokenStorage
    participant JWT as JwtEncoder
    participant AUD as SecurityEventService

    C->>I: POST /api/v1/auth/login {email,password}
    I->>AC: Public endpoint after origin/rate/body checks
    AC->>AS: login(request)
    AS->>LS: isLocked(normalizedEmail)
    LS->>LK: Check Redis global bucket, fallback to Caffeine on Redis failure
    alt Account locked
        AS->>AUD: LOGIN_FAILURE + ACCOUNT_LOCKED
        AS-->>AC: InvalidCredentialsException
        AC-->>C: 401/400 generic credential failure
    else Not locked
        AS->>DB: findByEmail(normalizedEmail)
        alt User not found
            AS->>ARG: Verify supplied password against dummy hash
            AS->>AUD: LOGIN_FAILURE unknown_account
            AS-->>C: Generic invalid credentials
        else User deleted
            AS->>ARG: Verify supplied password against dummy hash
            AS->>AUD: LOGIN_FAILURE deleted_account
            AS-->>C: Generic invalid credentials
        else User found
            AS->>ARG: Verify supplied password against stored Argon2id hash
            alt Argon2 capacity exhausted
                ARG-->>AS: AuthenticationCapacityExceededException
                AS-->>C: Capacity error
            else Password invalid
                AS->>LS: recordFailedAttempt(email)
                LS->>LK: Consume Caffeine then Redis lockout bucket
                AS->>AUD: LOGIN_FAILURE invalid_credentials
                opt Threshold now reached
                    AS->>AUD: ACCOUNT_LOCKED
                end
                AS-->>C: Generic invalid credentials
            else Password valid but email not confirmed
                AS->>AUD: LOGIN_FAILURE email_not_confirmed
                AS-->>C: EmailNotConfirmedException
            else Password valid and active
                AS->>LS: clearLockout(email)
                AS->>TS: storeRefreshToken(userId,jti,hashedToken,ttl)
                TS->>TS: Store token hash and family id in Redis hash
                AS->>JWT: Sign RS256 JWT with iss,aud,sub,jti,tenant_id,exp
                AS->>AUD: LOGIN_SUCCESS
                AC-->>C: 200 accessToken + HttpOnly refresh cookie + CSRF cookie
            end
        end
    end
```

## 2. Refresh Token Rotation

`POST /api/v1/auth/refresh`

Infrastructure role: refresh is public at the route layer but requires a valid refresh cookie; CSRF is enforced through double-submit cookie/header before service logic; token rotation is atomic in Redis Lua; reuse detection revokes the refresh-token family and emits critical audit/alert signals.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant I as Shared ingress filters
    participant AC as AuthController
    participant AS as AuthService
    participant DB as PostgreSQL users
    participant LS as AccountLockoutService
    participant TS as RedisTokenStorage
    participant JWT as JwtEncoder
    participant AUD as SecurityEventService

    C->>I: POST /api/v1/auth/refresh + Refresh-Token cookie + X-XSRF-TOKEN
    I->>AC: Public endpoint after origin/rate/body checks
    AC->>AC: Compare CSRF header with CSRF cookie
    alt Missing or mismatched CSRF
        AC-->>C: InvalidCsrfTokenException
    else CSRF valid or disabled
        AC->>AS: refresh(refreshCookie)
        AS->>AS: Parse opaque refresh token
        alt Malformed token
            AS->>AUD: REFRESH_TOKEN_FAILED malformed_refresh_token
            AS-->>C: InvalidRefreshTokenException
        else Token shape valid
            AS->>DB: findById(token.userId)
            alt User missing, deleted, unconfirmed, or locked
                AS->>AUD: REFRESH_TOKEN_FAILED
                AS-->>C: InvalidRefreshTokenException
            else User active
                AS->>LS: isLocked(user.email)
                AS->>TS: rotateRefreshToken(currentJti,currentRaw,nextJti,nextRaw)
                TS->>TS: Redis Lua validates current hash, deletes current JTI, stores next JTI
                alt Redis detects same-family reuse
                    TS-->>AS: TokenFamilyCompromisedException
                    AS->>AUD: REFRESH_TOKEN_REUSE_DETECTED critical
                    AS-->>C: Token family compromised
                else Rotation failed
                    AS->>AUD: REFRESH_TOKEN_FAILED refresh_rotation_failed
                    AS-->>C: InvalidRefreshTokenException
                else Rotation succeeded
                    AS->>JWT: Sign new access JWT bound to new jti
                    AS->>AUD: REFRESH_TOKEN_ROTATED
                    AC-->>C: 200 new accessToken + rotated refresh cookie + new CSRF cookie
                end
            end
        end
    end
```

## 3. Logout Current Session

`POST /api/v1/auth/logout`

Infrastructure role: logout is route-public to allow client cleanup, but CSRF is enforced when a refresh cookie is present; Redis validates the refresh token before revoking so forged logout audit events are not created; invalid or missing tokens are treated as idempotent cleanup.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant I as Shared ingress filters
    participant AC as AuthController
    participant AS as AuthService
    participant TS as RedisTokenStorage
    participant AUD as SecurityEventService

    C->>I: POST /api/v1/auth/logout + optional cookies
    I->>AC: Public endpoint after origin/rate/body checks
    AC->>AC: Validate CSRF if refresh cookie is present
    alt CSRF invalid
        AC-->>C: InvalidCsrfTokenException
    else CSRF valid or no refresh cookie
        AC->>AS: logout(refreshCookie)
        AS->>AS: Parse refresh token
        alt Token missing or malformed
            AS-->>AC: No-op
        else Token parses
            AS->>TS: validateToken(userId,jti,rawToken)
            alt Token hash does not match Redis
                AS-->>AC: No-op
            else Token valid
                AS->>TS: revokeSession(userId,jti)
                AS->>AUD: LOGOUT logout_current_session
            end
        end
        AC-->>C: 200 and clear refresh + CSRF cookies
    end
```

## 4. Logout All Sessions

`POST /api/v1/auth/logout-all`

Infrastructure role: this route requires a valid bearer access token; `UserAuthoritiesFilter` refreshes the live role/enabled snapshot from Caffeine or PostgreSQL before the controller executes; Redis deletes the entire refresh session hash for the user.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant I as Shared authenticated ingress
    participant AF as UserAuthoritiesFilter
    participant ACa as Authority Caffeine
    participant DB as PostgreSQL users
    participant AC as AuthController
    participant AS as AuthService
    participant TS as RedisTokenStorage
    participant AUD as SecurityEventService

    C->>I: POST /api/v1/auth/logout-all + Bearer JWT
    I->>AF: JWT valid
    AF->>ACa: Lookup authorities by jwt.sub
    alt Cache miss
        AF->>DB: findById(jwt.sub)
        DB-->>AF: Current user snapshot
        AF->>ACa: Cache authorities
    end
    alt User absent/disabled
        AF-->>C: 401 Unauthorized
    else Authorized
        AF->>AC: Continue
        AC->>AS: logoutAll(jwt.sub)
        AS->>DB: findById(userId)
        alt User deleted or missing
            AS-->>C: UserNotFoundException
        else User active
            AS->>TS: revokeAllSessions(userId)
            AS->>AUD: LOGOUT_ALL
            AC-->>C: 200 and clear refresh + CSRF cookies
        end
    end
```

## 5. Register

`POST /api/v1/auth/register`

Infrastructure role: request size and rate limits are enforced before Argon2 hashing; user and consent state are stored transactionally in PostgreSQL; activation email is written to the email outbox and later delivered through RabbitMQ and Resend outside the request transaction; duplicate behavior depends on `authkit.auth.registration.stealth-conflicts`.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant I as Shared ingress filters
    participant AC as AuthController
    participant RS as RegistrationService
    participant ARG as PasswordEncoder Argon2id
    participant DB as PostgreSQL users
    participant CE as ConsentEventService
    participant OB as EmailOutboxService
    participant OP as EmailOutboxProcessor
    participant MQ as RabbitMQ
    participant EL as RabbitMqEmailListener
    participant EP as ResendEmailClient

    C->>I: POST /api/v1/auth/register {email,password,terms,privacy}
    I->>AC: Public endpoint after origin/rate/body checks
    AC->>RS: registerUser(request)
    RS->>DB: findByEmail(normalizedEmail)
    alt Duplicate email
        RS-->>AC: UserAlreadyExistsException
        alt stealth-conflicts=true
            AC-->>C: 202 generic accepted response
        else stealth-conflicts=false
            AC-->>C: 409 Email already in use
        end
    else New email
        RS->>ARG: Encode password with Argon2id
        RS->>DB: save user with emailConfirmationTokenHash and consent snapshot
        alt Unique constraint race
            DB-->>RS: DataIntegrityViolationException
            RS-->>AC: UserAlreadyExistsException
        else Saved
            RS->>CE: recordCurrentConsent(user)
            CE->>DB: Insert append-only consent_event
            RS->>OB: enqueue activation email
            OB->>DB: Insert email_outbox PENDING in transaction
            AC-->>C: 201 RegisterResponse or 202 stealth response
            OP->>DB: Claim due outbox messages
            OP->>MQ: Publish EmailPayload
            OP->>DB: markSent or markFailed
            MQ->>EL: Deliver email job
            EL->>EP: Send activation email
        end
    end
```

## 6. Confirm Email

`POST /api/v1/auth/email-confirmation/confirm?token=...`

Infrastructure role: confirmation is public but still passes origin and rate-limit filters; only token hashes are expected in persistent user records, with a raw-token lookup fallback for migration compatibility; success emits a durable security event.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant I as Shared ingress filters
    participant AC as AuthController
    participant RS as RegistrationService
    participant DB as PostgreSQL users
    participant AUD as SecurityEventService

    C->>I: POST /api/v1/auth/email-confirmation/confirm?token=...
    I->>AC: Public endpoint after origin/rate checks
    AC->>RS: confirmEmail(token)
    alt Token blank
        RS-->>C: InvalidTokenException
    else Token supplied
        RS->>RS: sha256(token)
        RS->>DB: findByEmailConfirmationToken(hash), fallback raw token
        alt No matching token
            RS-->>C: InvalidTokenException
        else Match
            RS->>DB: set emailConfirmed=true, clear confirmation token
            RS->>AUD: EMAIL_VERIFIED
            AC-->>C: 200 Email confirmed
        end
    end
```

## 7. Request Password Recovery

`POST /api/v1/auth/password-recovery/request`

Infrastructure role: the endpoint intentionally returns the same success response for existing and non-existing accounts; existing accounts get a Redis recovery token and an outbox-backed email; unknown accounts still create a durable security event for abuse visibility.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant I as Shared ingress filters
    participant AC as AuthController
    participant PR as PasswordRecoveryService
    participant DB as PostgreSQL users
    participant TS as RedisTokenStorage
    participant OB as EmailOutboxService
    participant OP as EmailOutboxProcessor
    participant MQ as RabbitMQ
    participant EP as ResendEmailClient
    participant AUD as SecurityEventService

    C->>I: POST /api/v1/auth/password-recovery/request {email}
    I->>AC: Public endpoint after origin/rate/body checks
    AC->>PR: requestRecovery(email)
    PR->>DB: findByEmail(normalizedEmail)
    alt Existing user
        PR->>AUD: PASSWORD_RESET_REQUESTED target user
        PR->>TS: storeRecoveryToken(email, token hash, ttl)
        PR->>OB: enqueue reset email
        OB->>DB: Insert email_outbox PENDING
        OP->>MQ: Publish due email job
        MQ->>EP: Listener sends via Resend
    else Unknown user
        PR->>AUD: PASSWORD_RESET_REQUESTED stealth email hash
    end
    AC-->>C: 200 generic recovery response
```

## 8. Reset Password

`POST /api/v1/auth/password-recovery/reset?email=...`

Infrastructure role: recovery tokens are consumed atomically from Redis before password mutation; Argon2 encoding is concurrency-bounded; all refresh sessions are revoked; a password-change notification is outbox-backed; audit and lockout state are updated.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant I as Shared ingress filters
    participant AC as AuthController
    participant PR as PasswordRecoveryService
    participant TS as RedisTokenStorage
    participant DB as PostgreSQL users
    participant ARG as Argon2 limiter + PasswordEncoder
    participant LS as AccountLockoutService
    participant OB as EmailOutboxService
    participant AUD as SecurityEventService

    C->>I: POST /api/v1/auth/password-recovery/reset?email=... {token,newPassword}
    I->>AC: Public endpoint after origin/rate/body checks
    AC->>PR: resetPassword(email, token, newPassword)
    PR->>TS: consumeRecoveryToken(email, token)
    alt Token invalid, expired, or already consumed
        PR->>AUD: PASSWORD_RESET_FAILED invalid_or_expired_reset_token
        PR-->>C: InvalidTokenException
    else Token consumed
        PR->>DB: findByEmail(email)
        alt User missing or deleted
            PR->>AUD: PASSWORD_RESET_FAILED
            PR-->>C: UserNotFoundException
        else User active
            PR->>ARG: Encode new password
            alt Argon2 capacity exhausted
                ARG-->>PR: AuthenticationCapacityExceededException
            else Encoded
                PR->>DB: save password hash
                PR->>LS: clearLockout(email)
                PR->>TS: revokeAllSessions(userId)
                PR->>OB: enqueue password changed email
                PR->>AUD: PASSWORD_RESET_COMPLETED
                AC-->>C: 200 Password successfully reset
            end
        end
    end
```

## 9. Get My Profile

`GET /api/v1/users/me`

Infrastructure role: JWT is stateless, but live account status and roles are rehydrated through `UserAuthoritiesFilter`; profile access also enforces tenant match against the JWT `tenant_id` claim and rejects deleted accounts.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant I as Shared authenticated ingress
    participant AF as UserAuthoritiesFilter
    participant ACa as Authority Caffeine
    participant DB as PostgreSQL users
    participant UC as UserController
    participant PS as ProfileService

    C->>I: GET /api/v1/users/me + Bearer JWT
    I->>AF: JWT valid
    AF->>ACa: Lookup current authorities
    alt Cache miss
        AF->>DB: findById(jwt.sub)
        DB-->>AF: Current user snapshot
        AF->>ACa: Cache authorities briefly
    end
    alt Missing/disabled user
        AF-->>C: 401 Unauthorized
    else Authorized role USER/OWNER/ADMIN
        AF->>UC: getMyProfile(jwt)
        UC->>PS: getProfile(jwt.sub)
        PS->>DB: findById(jwt.sub)
        alt Tenant mismatch, deleted user, or missing user
            PS-->>C: UserNotFoundException
        else Active user
            PS-->>UC: ProfileResponse
            UC-->>C: 200 profile
        end
    end
```

## 10. Get My Consent Snapshot

`GET /api/v1/users/me/consent`

Infrastructure role: shares the authenticated ingress path; the service loads the active user, enforces tenant and email-confirmed status, then returns the current consent snapshot stored on the user row.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant I as Shared authenticated ingress
    participant UC as UserController
    participant ALS as AccountLifecycleService
    participant DB as PostgreSQL users

    C->>I: GET /api/v1/users/me/consent + Bearer JWT
    I->>UC: JWT valid and authorities current
    UC->>ALS: getConsentSnapshot(jwt.sub)
    ALS->>DB: findById(jwt.sub)
    alt Tenant mismatch, deleted, unconfirmed, or missing
        ALS-->>C: UserNotFoundException or EmailNotConfirmedException
    else Active user
        ALS-->>UC: ConsentSnapshotResponse
        UC-->>C: 200 consent snapshot
    end
```

## 11. Export My Data

`POST /api/v1/users/me/export`

Infrastructure role: this is a sensitive authenticated operation with current-password step-up; Argon2 verification is bounded; response aggregates user profile, current consent, consent history, deletion metadata, and a bounded set of privacy-safe security events; export itself is audited.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant I as Shared authenticated ingress
    participant UC as UserController
    participant ALS as AccountLifecycleService
    participant DB as PostgreSQL users
    participant ARG as Argon2 limiter + PasswordEncoder
    participant CE as consent_events
    participant SE as security_events
    participant AUD as SecurityEventService

    C->>I: POST /api/v1/users/me/export {currentPassword} + Bearer JWT
    I->>UC: JWT valid and authorities current
    UC->>ALS: exportUserData(jwt.sub, stepUpRequest)
    ALS->>DB: findById(jwt.sub)
    alt User inactive, tenant mismatch, or unconfirmed
        ALS-->>C: Access denied as not found/unconfirmed
    else Active user
        ALS->>ALS: Check currentPassword present and nonblank
        alt Missing/blank password
            ALS->>AUD: DATA_EXPORT_REQUESTED denied
            ALS-->>C: InvalidCredentialsException
        else Password supplied
            ALS->>ARG: Verify current password
            alt Invalid password
                ALS->>AUD: DATA_EXPORT_REQUESTED denied
                ALS-->>C: InvalidCredentialsException
            else Valid password
                ALS->>SE: Load recent target-user security events with configured limit
                ALS->>CE: Load consent history
                ALS->>AUD: DATA_EXPORT_REQUESTED success
                ALS-->>UC: UserDataExportResponse
                UC-->>C: 200 export payload
            end
        end
    end
```

## 12. Update My Profile

`PATCH /api/v1/users/me`

Infrastructure role: the endpoint has no user-id path parameter, so it is scoped to the JWT subject; the service still performs a subject equality check, tenant check, deleted-account check, and email-confirmed check before saving whitelisted profile fields.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant I as Shared authenticated ingress
    participant UC as UserController
    participant PS as ProfileService
    participant DB as PostgreSQL users

    C->>I: PATCH /api/v1/users/me {name?,phone?} + Bearer JWT
    I->>UC: JWT valid and authorities current
    UC->>PS: updateProfile(jwt.sub, request, jwt.sub)
    PS->>PS: Enforce targetUserId == authenticatedUserId
    alt Subject mismatch
        PS-->>C: UserNotFoundException
    else Subject matches
        PS->>DB: findById(jwt.sub)
        alt Tenant mismatch, deleted, unconfirmed, or missing
            PS-->>C: UserNotFoundException or EmailNotConfirmedException
        else Active user
            PS->>DB: save whitelisted profile fields
            PS-->>UC: ProfileResponse
            UC-->>C: 200 updated profile
        end
    end
```

## 13. Change My Password

`POST /api/v1/users/me/password`

Infrastructure role: this is a sensitive authenticated operation; it is blocked while the account is locked, requires current-password verification, bounds both Argon2 verification and encoding, revokes every Redis refresh session except the current access-token JTI, and emits high-severity security events.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant I as Shared authenticated ingress
    participant UC as UserController
    participant PS as ProfileService
    participant DB as PostgreSQL users
    participant LS as AccountLockoutService
    participant ARG as Argon2 limiter + PasswordEncoder
    participant TS as RedisTokenStorage
    participant AUD as SecurityEventService

    C->>I: POST /api/v1/users/me/password {currentPassword,newPassword} + Bearer JWT
    I->>UC: JWT valid and authorities current
    UC->>PS: changePassword(jwt.sub, request, jwt.jti)
    PS->>DB: findById(jwt.sub)
    alt Tenant mismatch, deleted, unconfirmed, or missing
        PS-->>C: UserNotFoundException or EmailNotConfirmedException
    else Active user
        PS->>LS: isLocked(user.email)
        alt Locked
            PS->>AUD: PASSWORD_CHANGED denied password_change_account_locked
            PS-->>C: AccountLockedException
        else Not locked
            PS->>ARG: Verify current password
            alt Invalid current password
                PS->>AUD: PASSWORD_CHANGED denied current_password_invalid
                PS-->>C: InvalidCredentialsException
            else Current password valid
                PS->>ARG: Encode new password
                PS->>DB: save new password hash
                PS->>TS: revokeOtherSessions(userId,currentJti)
                PS->>AUD: PASSWORD_CHANGED success
                UC-->>C: 200 password changed
            end
        end
    end
```

## 14. List My Sessions

`GET /api/v1/users/me/sessions`

Infrastructure role: the access token is stateless, but active refresh sessions are stateful and listed from Redis by JTI; user activity and tenant checks happen before exposing session identifiers.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant I as Shared authenticated ingress
    participant UC as UserController
    participant PS as ProfileService
    participant DB as PostgreSQL users
    participant TS as RedisTokenStorage

    C->>I: GET /api/v1/users/me/sessions + Bearer JWT
    I->>UC: JWT valid and authorities current
    UC->>PS: listSessions(jwt.sub)
    PS->>DB: findById(jwt.sub)
    alt Tenant mismatch, deleted, or missing
        PS-->>C: UserNotFoundException
    else Active user
        PS->>TS: listSessions(userId)
        TS-->>PS: Redis hash keys as active JTIs
        PS-->>UC: List<SessionResponse>
        UC-->>C: 200 sessions
    end
```

## 15. Revoke One Session

`DELETE /api/v1/users/me/sessions/{jti}`

Infrastructure role: revocation is scoped to the authenticated user's Redis refresh-token hash, which prevents cross-user session deletion; lockout blocks session management; success is audited as logout/session revocation.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant I as Shared authenticated ingress
    participant UC as UserController
    participant PS as ProfileService
    participant DB as PostgreSQL users
    participant LS as AccountLockoutService
    participant TS as RedisTokenStorage
    participant AUD as SecurityEventService

    C->>I: DELETE /api/v1/users/me/sessions/{jti} + Bearer JWT
    I->>UC: JWT valid and authorities current
    UC->>PS: revokeSession(jwt.sub, jti)
    PS->>DB: findById(jwt.sub)
    alt Tenant mismatch, deleted, or missing
        PS-->>C: UserNotFoundException
    else Active user
        PS->>LS: isLocked(user.email)
        alt Locked
            PS-->>C: AccountLockedException
        else Not locked
            PS->>TS: revokeSession(userId,jti)
            PS->>AUD: LOGOUT session_revoked
            UC-->>C: 200 session revoked
        end
    end
```

## 16. Delete My Account

`DELETE /api/v1/users/me`

Infrastructure role: deletion requires bearer auth and password step-up; user PII is anonymized immediately in PostgreSQL; authority cache is evicted and Redis sessions are revoked only after commit; deletion and anonymization are durable security events; retention jobs later purge deleted-account tombstones according to configuration.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant I as Shared authenticated ingress
    participant UC as UserController
    participant ALS as AccountLifecycleService
    participant DB as PostgreSQL users
    participant ARG as Argon2 limiter + PasswordEncoder
    participant ACa as Authority Caffeine
    participant TS as RedisTokenStorage
    participant AUD as SecurityEventService
    participant MET as MeterRegistry

    C->>I: DELETE /api/v1/users/me {currentPassword} + Bearer JWT
    I->>UC: JWT valid and authorities current
    UC->>ALS: requestDeletion(jwt.sub, stepUpRequest)
    ALS->>DB: findById(jwt.sub)
    alt User inactive, tenant mismatch, or unconfirmed
        ALS-->>C: Access denied as not found/unconfirmed
    else Active user
        ALS->>ARG: Verify current password
        alt Missing/invalid password
            ALS->>AUD: ACCOUNT_DELETION_REQUESTED denied
            ALS-->>C: InvalidCredentialsException
        else Valid password
            ALS->>ARG: Encode random replacement password
            ALS->>DB: mark deletion requested, deleted, anonymized; replace direct PII
            ALS-->>UC: AccountDeletionResponse
            UC-->>C: 200 deleted
            ALS->>ACa: afterCommit evict user authorities
            ALS->>TS: afterCommit revokeAllSessions(userId)
            alt Redis revocation fails
                ALS->>MET: security.infrastructure.failure component=token_storage
            end
            ALS->>AUD: ACCOUNT_DELETION_REQUESTED success
            ALS->>AUD: ACCOUNT_ANONYMIZED success
        end
    end
```

## 17. Get JWKS

`GET /.well-known/jwks.json`

Infrastructure role: this public endpoint publishes the active RSA public key and key id so downstream services can validate AuthKit JWTs statelessly without calling AuthKit on every request.

```mermaid
sequenceDiagram
    autonumber
    participant C as Downstream service or client
    participant I as Shared ingress filters
    participant JC as JwksController
    participant CFG as JwtConfig/AuthProperties

    C->>I: GET /.well-known/jwks.json
    I->>JC: Public endpoint after origin/rate checks
    JC->>CFG: getPublicKey() and authkit.auth.jwt.key-id
    JC-->>C: JWK Set with RSA public key, kid, use=sig, alg=RS256
```

## 18. Background Email Delivery Flow

This flow is not a direct controller endpoint, but it is part of registration, password recovery, and password reset completion.

Infrastructure role: request handlers only enqueue messages in PostgreSQL; the scheduler claims due rows in batches and publishes them to RabbitMQ; the listener sends through Resend outside the user transaction. Publish failures update the outbox row and increment infrastructure-failure metrics.

```mermaid
sequenceDiagram
    autonumber
    participant S as Registration/Recovery service
    participant OB as EmailOutboxService
    participant DB as PostgreSQL email_outbox
    participant OP as EmailOutboxProcessor scheduler
    participant MQ as RabbitMQ exchange/queue
    participant EL as RabbitMqEmailListener
    participant EP as ResendEmailClient
    participant MET as MeterRegistry

    S->>OB: enqueue(EmailPayload)
    OB->>DB: Insert PENDING in same app transaction
    OP->>DB: claimDueMessages(batchSize, lockTtl)
    DB-->>OP: Mark claimable rows PROCESSING
    loop Each claimed message
        OP->>MQ: publish EmailPayload
        alt Rabbit publish succeeds
            OP->>DB: markSent(messageId)
            MQ->>EL: Deliver message
            EL->>EP: Send email
        else Rabbit publish fails
            OP->>MET: security.infrastructure.failure component=email_outbox
            OP->>DB: markFailed(messageId,error)
        end
    end
```

## 19. Background Retention Flow

This flow is not a direct controller endpoint, but it supports production privacy and audit retention requirements.

Infrastructure role: `DataRetentionService` runs from the configured cron when enabled; it purges expired security events and deleted-account tombstones in bounded batches with new transactions per batch to avoid long-running delete transactions.

```mermaid
sequenceDiagram
    autonumber
    participant SCH as Scheduler
    participant DRS as DataRetentionService
    participant SE as security_events
    participant DB as users

    SCH->>DRS: purgeExpiredSecurityEvents() on cron
    loop Bounded security-event batches
        DRS->>SE: findExpiredIds(cutoff, PageRequest(batchSize))
        alt No expired ids
            DRS-->>SCH: Done
        else Expired ids found
            DRS->>SE: purgeByIdIn(ids) in REQUIRES_NEW transaction
        end
    end
    loop Bounded deleted-user batches
        DRS->>DB: findDeletedIdsBefore(cutoff, PageRequest(batchSize))
        alt No expired tombstones
            DRS-->>SCH: Done
        else Expired tombstones found
            DRS->>DB: purgeDeletedByIdIn(ids) in REQUIRES_NEW transaction
        end
    end
```

## Production Readiness Note

The current architecture is intentionally stateless for access-token verification: issued access tokens are self-contained RS256 JWTs, downstream services can verify them using JWKS, and AuthKit does not create server-side HTTP sessions. The stateful parts are deliberate security state: refresh-token families, recovery tokens, distributed rate-limit buckets, lockout buckets, authority snapshots, email outbox rows, and durable audit/consent records.

Production strengths visible in the current implementation:

- Reverse-proxy trust boundary is enforced in Kubernetes and in application filters.
- Volumetric protection happens before JSON parsing and password hashing.
- Password hashing work is concurrency-bounded to reduce hashing DoS risk.
- Refresh tokens are HttpOnly cookies, server-side hashed in Redis, rotated atomically, and family reuse is audited as critical.
- Authenticated routes rehydrate live authorities instead of trusting stale JWT roles indefinitely.
- Email delivery is outbox-backed and does not hold user transactions open while calling RabbitMQ or Resend.
- Security and consent events are durable, privacy-safe, metric-backed, and alertable.
- Account export/deletion require current-password step-up.

Operational caveats to keep in mind before production:

- Redis is a hard dependency for refresh tokens and recovery tokens; rate limiting and lockout have local fallback, but token flows do not.
- The Kubernetes service is intended to sit behind an ingress controller; real client IP handling depends on trusted ingress/proxy headers and the configured `network.proxy-depth`.
- No frontend is included in this repository; browser storage, XSS controls, and redirect UX must be validated in the consuming application.
- `/actuator/prometheus` is intentionally public in the app security rules; production exposure should be constrained by Kubernetes network policy, ingress rules, or monitoring-network controls.
- NetworkPolicy cannot restrict Resend egress by FQDN; production clusters should use an egress gateway, DNS policy, or cloud firewall where available.
- Downstream services must validate JWT issuer, audience, expiration, signature, and `kid`, and should not call AuthKit per request unless they need a live revocation/authorization decision beyond token TTL.
