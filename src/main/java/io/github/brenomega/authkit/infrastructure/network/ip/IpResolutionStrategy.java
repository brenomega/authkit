package io.github.brenomega.authkit.infrastructure.network.ip;

import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;

public interface IpResolutionStrategy {

    Optional<String> resolveIp(HttpServletRequest request);

    int getOrder();
}
