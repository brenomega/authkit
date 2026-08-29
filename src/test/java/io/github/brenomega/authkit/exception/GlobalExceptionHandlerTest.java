package io.github.brenomega.authkit.exception;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class GlobalExceptionHandlerTest {

    @Test
    void revocationStoreFailureUsesFailClosedOAuthWireError() {
        var response = new GlobalExceptionHandler(new SimpleMeterRegistry())
                .handleTokenRevocationUnavailable(new TokenRevocationUnavailableException());

        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
        assertEquals("temporarily_unavailable", response.getBody().get("error"));
        assertEquals("no-store", response.getHeaders().getCacheControl());
        assertEquals("no-cache", response.getHeaders().getPragma());
    }
}
