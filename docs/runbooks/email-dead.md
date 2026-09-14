# Email DEAD state

List DEAD outbox rows by ID, recipient hash, attempt count and provider response without exposing message bodies or tokens. Resolve provider credentials, quota, TLS or template failure first. Check the provider by stable outbox/message identity before replaying so an accepted message is not duplicated. Replay only through the documented outbox operation and verify the row reaches `ACCEPTED`; retain incident evidence.
