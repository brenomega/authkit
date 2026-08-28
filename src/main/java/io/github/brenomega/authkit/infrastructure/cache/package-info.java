/**
 * Provides Redis-backed token state and distributed rate-limit support. Token
 * mutations that require replay resistance use server-side scripts so validation
 * and state transition occur atomically within Redis.
 */
package io.github.brenomega.authkit.infrastructure.cache;
