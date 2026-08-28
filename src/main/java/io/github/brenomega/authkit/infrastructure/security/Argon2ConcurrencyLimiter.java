package io.github.brenomega.authkit.infrastructure.security;

import java.util.concurrent.Semaphore;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Bounds concurrent Argon2 operations to protect process memory and availability.
 * A configured value of zero derives the limit from available processors; admission
 * is non-blocking so callers can reject excess authentication work promptly.
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

    /** Attempts immediate admission without waiting for capacity. */
    public boolean tryAcquire() {
        return semaphore.tryAcquire();
    }

    /** Releases one permit previously obtained by the caller. */
    public void release() {
        semaphore.release();
    }

    public int maxConcurrent() {
        return maxConcurrent;
    }
}
