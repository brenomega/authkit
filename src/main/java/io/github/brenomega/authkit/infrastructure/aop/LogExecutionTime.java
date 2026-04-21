package io.github.brenomega.authkit.infrastructure.aop;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marker annotation to enable automatic execution-time logging for a method.
 *
 * <p>When applied to a public method of a Spring-managed bean, the
 * {@link LoggingAspect} intercepts the call and records its elapsed
 * execution time at {@code DEBUG} level (DT 3.4.8).</p>
 *
 * <p>Usage example:</p>
 * <pre>{@code
 * @LogExecutionTime
 * public void processPayment(PaymentDTO dto) { ... }
 * }</pre>
 *
 * @see LoggingAspect
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface LogExecutionTime {
}
