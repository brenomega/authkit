package io.github.brenomega.authkit.infrastructure.network.ip;

import java.util.Optional;

import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

@Component
public class DirectIpStrategy implements IpResolutionStrategy {

    @Override
    public Optional<String> resolveIp(HttpServletRequest request) {
        return Optional.ofNullable(request.getRemoteAddr());
    }

    @Override
    public int getOrder() {
        return 300;
    }
}
