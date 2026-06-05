package io.github.brenomega.authkit.infrastructure.security;

import java.util.concurrent.Semaphore;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Centralized concurrency limiter for Argon2id hash computations (DT 3.2.26).
 *
 * <p>Wraps a single {@link Semaphore} shared across all services that perform
 * password hashing, ensuring the system-wide thread exhaustion guard operates
 * as a coordinated unit rather than as independent per-service limiters.</p>
 *
 * <p>Permit count is operator-configurable. Zero selects {@code max(2, cores * 1.5)}.</p>
 */
@Component
public class Argon2ConcurrencyLimiter {

    private final Semaphore semaphore;
    private final int maxConcurrent;

    public Argon2ConcurrencyLimiter() {
        this(0);
    }

    @Autowired
    public Argon2ConcurrencyLimiter(@Value("${security.argon2.max-concurrent:0}") int configuredMaxConcurrent) {
        int automatic = Math.max(2, (int) (Runtime.getRuntime().availableProcessors() * 1.5));
        this.maxConcurrent = configuredMaxConcurrent == 0 ? automatic : configuredMaxConcurrent;
        if (maxConcurrent < 1) {
            throw new IllegalArgumentException("security.argon2.max-concurrent must be zero or positive");
        }
        this.semaphore = new Semaphore(maxConcurrent);
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

    public int maxConcurrent() {
        return maxConcurrent;
    }
}
