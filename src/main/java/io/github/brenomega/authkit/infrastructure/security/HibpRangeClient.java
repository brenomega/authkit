package io.github.brenomega.authkit.infrastructure.security;

import java.io.IOException;

/**
 * Retrieves a HIBP k-anonymity range without receiving a complete password hash.
 *
 * <p>Callers supply only the first five hexadecimal characters of an uppercase
 * SHA-1 digest. Implementations must not send the raw password or full digest.</p>
 */
@FunctionalInterface
public interface HibpRangeClient {

    /**
     * Fetches suffix/count entries matching a SHA-1 prefix.
     *
     * @throws IOException if the remote range cannot be retrieved
     * @throws InterruptedException if the calling thread is interrupted while
     *         waiting for the response
     */
    String fetchRange(String sha1Prefix) throws IOException, InterruptedException;
}
