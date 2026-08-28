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

@Aspect
@Component
public class LoggingAspect {

    private static final Logger log = LoggerFactory.getLogger(LoggingAspect.class);

    private static final Set<String> SENSITIVE_PARAMS = Set.of(
            "password", "token", "secret", "accesstoken", "refreshtoken",
            "jwt", "authorization", "currentpassword", "newpassword",
            "rawtoken", "rawrefreshtoken", "mfatoken", "mfacode",
            "code", "otp", "totp", "backupcode", "backupcodes"
    );

    private static final String MASKED = "[REDACTED]";

    @Pointcut("@annotation(LogExecutionTime)")
    public void logExecutionTimeAnnotation() {

    }

    @Pointcut("execution(* io.github.brenomega.authkit.service..*.*(..))")
    public void serviceLayer() {

    }

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

    @AfterReturning("serviceLayer()")
    public void logServiceCompletion(JoinPoint joinPoint) {
        String methodName = joinPoint.getSignature().toShortString();
        log.info("< Use-case completed: {}", methodName);
    }

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

    static boolean isSensitive(String paramName) {
        String normalized = paramName.toLowerCase();
        return SENSITIVE_PARAMS.contains(normalized)
                || normalized.contains("password")
                || normalized.contains("secret")
                || normalized.contains("token")
                || normalized.contains("authorization")
                || normalized.contains("credential")
                || normalized.contains("assertion")
                || normalized.contains("attestation")
                || normalized.contains("mfacode");
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
                || simpleName.contains("stepuprequest")
                || simpleName.contains("passkey")
                || simpleName.contains("oauth")
                || simpleName.contains("mfa");
    }
}
