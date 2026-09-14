package io.github.brenomega.authkit.exception;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.CannotCreateTransactionException;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class GlobalExceptionHandlerTest {

    @Test
    void databaseConnectionFailureIsAnOpaqueServiceUnavailableResponse() {
        var meterRegistry = new SimpleMeterRegistry();
        var response = new GlobalExceptionHandler(meterRegistry)
                .handlePersistenceUnavailable(new DataAccessResourceFailureException("jdbc:postgresql://secret-host"));

        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
        assertEquals("persistence_unavailable", response.getBody().code());
        assertEquals("Service temporarily unavailable", response.getBody().errors().getFirst());
        assertEquals(1.0, meterRegistry.counter(
                "security.infrastructure.failure", "component", "postgres").count());
    }

    @Test
    void transactionCreationFailureIsServiceUnavailable() {
        var response = new GlobalExceptionHandler(new SimpleMeterRegistry())
                .handlePersistenceUnavailable(new CannotCreateTransactionException("database unavailable"));

        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
    }

    @Test
    void genericDataIntegrityFailureRemainsInternalServerError() {
        var response = new GlobalExceptionHandler(new SimpleMeterRegistry())
                .handleDataAccess(new DuplicateKeyException("constraint internals"));

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("Internal Server Error", response.getBody().errors().getFirst());
    }

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
