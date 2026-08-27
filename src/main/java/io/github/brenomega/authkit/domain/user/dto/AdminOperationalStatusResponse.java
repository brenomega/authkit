package io.github.brenomega.authkit.domain.user.dto;

import java.util.Map;

public record AdminOperationalStatusResponse(
        Map<String, Long> emailOutbox,
        String emailDispatchMode,
        String tokenStorageBackend,
        boolean retentionWorkerEnabled
) {}
