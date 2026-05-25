package io.github.brenomega.authkit.infrastructure.security;

import java.util.concurrent.Semaphore;

import org.springframework.stereotype.Component;

/**
 * Centralized concurrency limiter for Argon2id hash computations (DT 3.2.26).
 *
 * <p>Wraps a single {@link Semaphore} shared across all services that perform
 * password hashing, ensuring the system-wide thread exhaustion guard operates
 * as a coordinated unit rather than as independent per-service limiters.</p>
 *
 * <p>Permit count: {@code max(2, cores × 1.5)}.</p>
 */
@Component
public class Argon2ConcurrencyLimiter {

    private final Semaphore semaphore;

    public Argon2ConcurrencyLimiter() {
        int permits = (int) (Runtime.getRuntime().availableProcessors() * 1.5);
        this.semaphore = new Semaphore(Math.max(2, permits));
    }

    /**
     * Attempts to acquire a permit without blocking.
     *
     * @return {@code true} if the permit was acquired
     */
    public boolean tryAcquire() {
        return semaphore.tryAcquire();
    }

    /**
     * Releases a previously acquired permit.
     */
    public void release() {
        semaphore.release();
    }
}
