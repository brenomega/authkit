package io.github.brenomega.authkit.infrastructure.security;

import java.io.IOException;

/**
 * Fetches a Have I Been Pwned password range without receiving a full password hash.
 * Implementations must transmit only the supplied five-character SHA-1 prefix and
 * must report transport and interruption failures rather than interpreting them as
 * a clean password result.
 */
@FunctionalInterface
public interface HibpRangeClient {

    /**
     * Returns the range response for a SHA-1 prefix.
     *
     * @throws IOException if a successful response cannot be obtained
     * @throws InterruptedException if the calling thread is interrupted while waiting
     */
    String fetchRange(String sha1Prefix) throws IOException, InterruptedException;
}
