package io.github.brenomega.authkit.infrastructure.security;

import java.io.IOException;

@FunctionalInterface
public interface HibpRangeClient {

    String fetchRange(String sha1Prefix) throws IOException, InterruptedException;
}
