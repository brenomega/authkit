package io.github.brenomega.authkit.infrastructure.network.ip;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import jakarta.servlet.http.HttpServletRequest;

class XForwardedForIpStrategyTest {

    @Test
    void resolvesClientBehindOneTrustedProxy() {
        HttpServletRequest request = requestWith("203.0.113.7");

        assertThat(new XForwardedForIpStrategy(1).resolveIp(request))
                .contains("203.0.113.7");
    }

    @Test
    void ignoresSpoofedLeftmostValueBehindOneTrustedProxy() {
        HttpServletRequest request = requestWith("198.51.100.99, 203.0.113.7");

        assertThat(new XForwardedForIpStrategy(1).resolveIp(request))
                .contains("203.0.113.7");
    }

    @Test
    void resolvesClientBehindTwoTrustedProxies() {
        HttpServletRequest request = requestWith("198.51.100.99, 203.0.113.7, 10.0.0.10");

        assertThat(new XForwardedForIpStrategy(2).resolveIp(request))
                .contains("203.0.113.7");
    }

    @Test
    void rejectsHeaderShorterThanTrustedProxyDepth() {
        HttpServletRequest request = requestWith("203.0.113.7");

        assertThat(new XForwardedForIpStrategy(2).resolveIp(request)).isEmpty();
    }

    private HttpServletRequest requestWith(String value) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("X-Forwarded-For")).thenReturn(value);
        return request;
    }
}
