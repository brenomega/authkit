# Key or credential rotation

Identify the previous worker token or retiring JWT/MFA key still in use. Confirm all consumers received the new key ID and material, then roll consumers individually and observe authentication. Do not remove previous verification/decryption material until the overlap and maximum token/message lifetime expire. After prior-key traffic reaches zero, revoke/remove it, verify unknown and revoked `kid` rejection, and record both old/new key IDs without secret material.

`AuthKitKeyLifecycleFailure` is critical for runtime
`security_key_lifecycle_failure_total{family="signing|jwks|mfa"}`. Signing,
JWKS-publication and MFA encryption/decryption failures preserve their original
exceptions. Restore correct current/previous key material before resuming rotation;
never disable signature or authentication-tag verification. Startup configuration
failures cannot be scraped, so monitor application availability during rotation.

## Audit pepper: coordinated invalidation

v0.1 accepts one audit pepper, with no online overlap or previous-root fallback.
Rotation intentionally invalidates recovery lookup digests (Redis and JDBC),
pending recovery activation/revocation intents, unused MFA backup-code hashes,
endpoint/account abuse bucket dimensions, and administrative cursor signatures.
Audit pseudonyms and security/consent event hashes also depend on the root.
Refresh-token hashes, JWT keys, TOTP encryption and account lockout use separate
state/roots. Redis session cursors are opaque random handles, not pepper signatures.

1. Record UTC, candidate tree/source SHA/OCI digest and old/new secret **version
   IDs**. Establish edge maintenance with existing abuse protection active. Drain
   `security_effects_outstanding` to zero and all recovery emails through terminal
   states. Restore failed dependencies and wait for automatic reconciliation or
   cancellation of expired activations; never rotate with unresolved effects.
2. Preserve encrypted PostgreSQL/Redis backups and the old pepper in the restricted
   historical audit-verification archive, bound to cutover time/event IDs. Do not
   rewrite historical hashes. Archived old material is offline verification-only,
   subject to audit retention, and must never be loaded into the application.
3. Stop AuthKit and its jobs, leaving PostgreSQL/Redis running. In the isolated
   drill stack, run the commands below with validated container names. They
   deliberately invalidate outstanding recovery, unused backup codes and abuse
   budgets. Tell affected users to request fresh links and regenerate backup codes
   after ordinary strong authentication.
4. Replace the mounted pepper through the secret store and recreate AuthKit using
   the public Compose procedure. Restart clears local abuse buckets as well.
   Administrative cursors signed by the old root are rejected. Keep edge controls
   active; reset abuse budgets are an explicit maintenance consequence.
5. Before reopening, prove old recovery links/backup codes/admin cursors fail,
   new recovery/cursors work, TOTP/passkey/password remain usable, and new backup
   codes can be generated after step-up. Verify zero unresolved effects, DEAD
   email, critical audit loss and integrity errors. Retain redacted outcomes,
   counts, metrics and secret-version IDs, never raw secrets.

Set `AUTHKIT_APP_CONTAINER`, `AUTHKIT_POSTGRES_CONTAINER`, and
`AUTHKIT_REDIS_CONTAINER` to the three validated golden containers:

```sh
docker stop "$AUTHKIT_APP_CONTAINER"
docker exec -i "$AUTHKIT_POSTGRES_CONTAINER" sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' <<'SQL'
BEGIN;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM security_effect_outbox WHERE status <> 'COMPLETED')
  THEN RAISE EXCEPTION 'unresolved security effects'; END IF;
END $$;
DELETE FROM auth_recovery_tokens;
DELETE FROM auth_recovery_activations;
UPDATE mfa_backup_codes SET used_at = CURRENT_TIMESTAMP WHERE used_at IS NULL;
COMMIT;
SQL
docker exec "$AUTHKIT_REDIS_CONTAINER" sh -c '
  export REDISCLI_AUTH="$(cat /run/secrets/redis_password)"
  for pattern in "recovery:*" "login_*:*" "mfa_*:*" "passkey_*:*" "registration_*:*" "email_confirmation_*:*" "password_recovery_*:*" "password_reset_*:*" "refresh_ip:*" "oauth_*:*" "admin_write_tenant:*" "profile_write_user:*" "step_up_*:*" "account_deletion_user:*" "session_list_user:*"; do
    redis-cli --scan --pattern "$pattern" | while IFS= read -r key; do
      redis-cli UNLINK "$key" >/dev/null
    done
  done'
```

Recreate using the new secret version; a simple restart can retain an old
environment value. Rollback requires matched database/Redis/pepper backups under
maintenance, never the old root alone against new-root live state. Local drill:
`./mvnw -Dtest=CrossStoreAtomicityIntegrationTest#coordinatedPepperInvalidationRejectsOldRecoveryBackupAndCursorState test`.
