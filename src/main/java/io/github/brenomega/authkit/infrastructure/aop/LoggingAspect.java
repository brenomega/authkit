package io.github.brenomega.authkit.infrastructure.aop;

import java.lang.reflect.Parameter;
import java.util.Set;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import io.github.brenomega.authkit.domain.user.util.EmailMasker;

/**
 * Cross-cutting aspect that centralizes application logging (DT 3.4.1, DT 3.4.8).
 *
 * <p>Responsibilities:</p>
 * <ul>
 *   <li><strong>Performance monitoring</strong> — logs the execution time of methods
 *       annotated with {@link LogExecutionTime} at {@code DEBUG} level.</li>
 *   <li><strong>Use-case completion</strong> — logs a summary message at {@code INFO}
 *       level when any service-layer method returns successfully.</li>
 *   <li><strong>PII sanitization</strong> — masks sensitive parameter values
 *       (passwords, tokens, CPF, CNPJ) before they can appear in log output
 *       (DT 3.4.1, DT 3.4.9).</li>
 * </ul>
 *
 * <p>All output is emitted via SLF4J to {@code stdout}.</p>
 */
@Aspect
@Component
public class LoggingAspect {

    private static final Logger log = LoggerFactory.getLogger(LoggingAspect.class);

    /**
     * Parameter names whose values must never be written to logs.
     */
    private static final Set<String> SENSITIVE_PARAMS = Set.of(
            "password", "token", "secret", "accesstoken", "refreshtoken",
            "jwt", "authorization", "currentpassword", "newpassword",
            "rawtoken", "rawrefreshtoken"
    );

    /** Replacement value for masked parameters. */
    private static final String MASKED = "[REDACTED]";

    // -------------------------------------------------------------------------
    // Pointcuts
    // -------------------------------------------------------------------------

    /**
     * Matches any method annotated with {@link LogExecutionTime}.
     */
    @Pointcut("@annotation(LogExecutionTime)")
    public void logExecutionTimeAnnotation() {
        // pointcut declaration, no body required
    }

    /**
     * Matches every public method inside the service layer.
     */
    @Pointcut("execution(* io.github.brenomega.authkit.service..*.*(..))")
    public void serviceLayer() {
        // pointcut declaration, no body required
    }

    // -------------------------------------------------------------------------
    // Advices
    // -------------------------------------------------------------------------

    /**
     * Measures and logs elapsed execution time at {@code DEBUG} level for
     * methods annotated with {@link LogExecutionTime} (DT 3.4.8).
     *
     * @param joinPoint the intercepted join point
     * @return the original return value of the intercepted method
     * @throws Throwable if the intercepted method throws
     */
    @Around("logExecutionTimeAnnotation()")
    public Object logExecutionTime(ProceedingJoinPoint joinPoint) throws Throwable {
        String methodName = joinPoint.getSignature().toShortString();
        String sanitizedArgs = sanitizeArguments(joinPoint);

        log.debug("> Entering {} with args: [{}]", methodName, sanitizedArgs);

        long start = System.currentTimeMillis();
        try {
            Object result = joinPoint.proceed();
            long elapsed = System.currentTimeMillis() - start;
            log.debug("< {} completed in {} ms", methodName, elapsed);
            return result;
        } catch (Throwable ex) {
            long elapsed = System.currentTimeMillis() - start;
            log.debug("< {} failed after {} ms: {}", methodName, elapsed, ex.getClass().getSimpleName());
            throw ex;
        }
    }

    /**
     * Logs a success summary at {@code INFO} level whenever a service-layer
     * method returns normally (DT 3.4.1 — INFO for use-case completion).
     *
     * @param joinPoint the intercepted join point
     */
    @AfterReturning("serviceLayer()")
    public void logServiceCompletion(JoinPoint joinPoint) {
        String methodName = joinPoint.getSignature().toShortString();
        log.info("< Use-case completed: {}", methodName);
    }

    // -------------------------------------------------------------------------
    // Sanitization helpers (DT 3.4.1, DT 3.4.9)
    // -------------------------------------------------------------------------

    /**
     * Builds a sanitized string representation of a method's arguments.
     *
     * <p>Any parameter whose name (case-insensitive) matches a known
     * sensitive keyword is replaced with {@value #MASKED}.</p>
     *
     * @param joinPoint the intercepted join point
     * @return a comma-separated string of safe argument representations
     */
    String sanitizeArguments(JoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Parameter[] params = signature.getMethod().getParameters();
        Object[] args = joinPoint.getArgs();

        if (params.length == 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < params.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            String paramName = params[i].getName();
            if (isSensitive(paramName) || isSensitiveValue(args[i])) {
                sb.append(paramName).append('=').append(MASKED);
            } else if (isEmail(paramName) && args[i] instanceof CharSequence email) {
                sb.append(paramName).append('=').append(EmailMasker.mask(email.toString()));
            } else if (args[i] instanceof CharSequence text && text.toString().contains("@")) {
                sb.append(paramName).append('=').append(EmailMasker.mask(text.toString()));
            } else if (args[i] instanceof CharSequence) {
                sb.append(paramName).append('=').append(MASKED);
            } else if (isEmail(paramName)) {
                sb.append(paramName).append('=').append(EmailMasker.mask(String.valueOf(args[i])));
            } else {
                sb.append(paramName).append('=').append(args[i]);
            }
        }
        return sb.toString();
    }

    /**
     * Checks whether a parameter name corresponds to sensitive data.
     *
     * @param paramName the name of the method parameter
     * @return {@code true} if the value should be masked
     */
    static boolean isSensitive(String paramName) {
        return SENSITIVE_PARAMS.contains(paramName.toLowerCase());
    }

    private static boolean isEmail(String paramName) {
        return paramName != null && paramName.toLowerCase().contains("email");
    }

    private static boolean isSensitiveValue(Object value) {
        if (value == null) {
            return false;
        }

        String simpleName = value.getClass().getSimpleName().toLowerCase();
        return simpleName.contains("loginrequest")
                || simpleName.contains("registerrequest")
                || simpleName.contains("passwordchangerequest")
                || simpleName.contains("passwordresetrequest")
                || simpleName.contains("passwordrecoveryrequest")
                || simpleName.contains("stepuprequest");
    }
}
