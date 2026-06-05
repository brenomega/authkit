package io.github.brenomega.authkit.infrastructure.security;

import java.io.IOException;

/** Boundary for the HIBP k-anonymity range API. */
@FunctionalInterface
public interface HibpRangeClient {

    String fetchRange(String sha1Prefix) throws IOException, InterruptedException;
}
