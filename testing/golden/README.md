# Local golden-path proof overlay

This test-only overlay adds Mailpit with mandatory STARTTLS to the production golden Compose. It does not weaken the AuthKit `prod` profile, TLS proxy, mounted-secret, database-role, Redis, HIBP, or email-template configuration. Build the mounted trust store from the candidate JVM's public CA set plus the generated local Mailpit CA; a local-CA-only trust store would break outbound HTTPS such as HIBP:

```sh
testing/golden/prepare-smtp-truststore.sh \
  /secure/local-proof/ca.pem \
  /secure/local-proof/secrets/smtp-truststore.p12
```

Mailpit proves local SMTP protocol acceptance only. It is not evidence for a real SMTP provider, Resend, inbox delivery, spam placement, public TLS, or either browser topology. Never use this overlay in production or report it as Gate 3/4 proof.
