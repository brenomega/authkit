package io.github.brenomega.authkit.response;

import java.util.UUID;
import org.slf4j.MDC;

/** Request correlation context shared by envelopes and edge filters. */
public final class RequestContext {
    public static final String MDC_KEY = "requestId";
    public static final String HEADER = "X-Request-ID";

    private RequestContext() {
    }

    public static String currentRequestId() {
        String current = MDC.get(MDC_KEY);
        return current == null || current.isBlank() ? UUID.randomUUID().toString() : current;
    }
}
