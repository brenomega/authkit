package io.github.brenomega.authkit.domain.user.dto;

import java.util.Map;

/** Carries security-relevant operational counts visible to platform administration. */
public record AdminOperationalStatusResponse(
        Map<String, Long> emailOutbox,
        String emailDispatchMode,
        String tokenStorageBackend,
        boolean retentionWorkerEnabled
) {}
