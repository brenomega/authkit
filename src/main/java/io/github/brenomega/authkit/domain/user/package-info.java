/**
 * Defines account state, identity, consent, password history, and user-facing
 * transfer types. Account identity is a UUID and each non-deleted account belongs
 * to one tenant; tenant authorization is enforced by services rather than inferred
 * from entity relationships alone.
 */
package io.github.brenomega.authkit.domain.user;
