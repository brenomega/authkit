/**
 * Provides relational infrastructure adapters and tenant-filter integration.
 * JDBC token storage uses database transactions and row locking for one-time state;
 * production use without Redis is restricted to explicit single-instance mode.
 */
package io.github.brenomega.authkit.infrastructure.persistence;
