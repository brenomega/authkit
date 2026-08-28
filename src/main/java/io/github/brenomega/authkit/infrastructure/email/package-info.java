/**
 * Adapts rendered email payloads to Resend, SMTP, or development logging. Provider
 * acceptance is not end-recipient delivery; retry and dead-letter policy belongs
 * to the outbox layer.
 */
package io.github.brenomega.authkit.infrastructure.email;
