package io.github.brenomega.authkit.infrastructure.security;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;
import io.micrometer.core.instrument.MeterRegistry;

/** Emits bounded key-family signals while preserving the original fail-closed exception. */
@Aspect
@Component
public class KeyLifecycleFailureMetrics {
    private final MeterRegistry meters;

    public KeyLifecycleFailureMetrics(MeterRegistry meters) {
        this.meters = meters;
    }

    public org.springframework.security.oauth2.jwt.JwtEncoder signingEncoder(
            org.springframework.security.oauth2.jwt.JwtEncoder delegate) {
        return parameters -> {
            try {
                return delegate.encode(parameters);
            } catch (RuntimeException failure) {
                meters.counter("security.key.lifecycle.failure", "family", "signing").increment();
                throw failure;
            }
        };
    }

    @Around("execution(* io.github.brenomega.authkit.infrastructure.security.JwtKeyService.publishedPublicJwkSet(..))")
    public Object jwks(ProceedingJoinPoint call) throws Throwable {
        return observe(call, "jwks");
    }

    @Around("execution(* io.github.brenomega.authkit.infrastructure.security.MfaSecretCipher.decrypt(..)) || "
            + "execution(* io.github.brenomega.authkit.infrastructure.security.MfaSecretCipher.encrypt(..))")
    public Object mfa(ProceedingJoinPoint call) throws Throwable {
        return observe(call, "mfa");
    }

    private Object observe(ProceedingJoinPoint call, String family) throws Throwable {
        try {
            return call.proceed();
        } catch (RuntimeException failure) {
            meters.counter("security.key.lifecycle.failure", "family", family).increment();
            throw failure;
        }
    }
}
