package io.github.brenomega.authkit.infrastructure.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DiagnosticsRedactionTest {

    @TempDir
    Path tempDir;

    @Test
    void bundleRedactsCurrentPreviousAndRotationSecretsAndUsesRestrictiveModes() throws Exception {
        Map<String, String> secrets = new LinkedHashMap<>();
        secrets.put("WORKER_TOKEN", "sentinel-current-worker-9fcb");
        secrets.put("WORKER_PREVIOUS_TOKENS", "sentinel-previous-worker-00a1");
        secrets.put("AUTH_MFA_SECRET_ENCRYPTION_KEY", "sentinel-current-mfa-key-aa12");
        secrets.put("AUTH_MFA_PREVIOUS_SECRET_ENCRYPTION_KEYS", "sentinel-previous-mfa-key-bb23");
        secrets.put("JWT_PRIVATE_KEY", "sentinel-private-jwt-cc34");
        secrets.put("JWT_RETIRING_PRIVATE_KEYS", "sentinel-retiring-jwt-dd45");
        secrets.put("DB_PASSWORD", "sentinel-database-ee56");
        secrets.put("REDIS_PASSWORD", "sentinel-redis-ff67");
        secrets.put("RESEND_API_KEY", "sentinel-resend-1168");
        secrets.put("AUTH_EMAIL_SMTP_PASSWORD", "sentinel-smtp-2269");
        secrets.put("AUTH_AUDIT_HASH_PEPPER", "sentinel-pepper-337a");
        secrets.put("OIDC_CLIENT_SECRET", "sentinel-oidc-447b");

        Path bundle = tempDir.resolve("bundle");
        ProcessBuilder builder = new ProcessBuilder("bash", "deploy/scripts/collect-diagnostics.sh");
        builder.directory(Path.of(".").toAbsolutePath().normalize().toFile());
        builder.redirectErrorStream(true);
        builder.environment().put("AUTHKIT_DIAGNOSTICS_DIR", bundle.toString());
        builder.environment().put("AUTHKIT_BASE_URL", "http://127.0.0.1:1");
        builder.environment().putAll(secrets);
        Process process = builder.start();
        String output = new String(process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        assertEquals(0, process.waitFor(), output);

        Set<PosixFilePermission> forbidden = Set.of(
                PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE,
                PosixFilePermission.GROUP_EXECUTE, PosixFilePermission.OTHERS_READ,
                PosixFilePermission.OTHERS_WRITE, PosixFilePermission.OTHERS_EXECUTE);
        try (var paths = Files.walk(bundle)) {
            for (Path path : paths.toList()) {
                Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path);
                assertTrue(java.util.Collections.disjoint(permissions, forbidden), path + " " + permissions);
                if (Files.isRegularFile(path)) {
                    String content = Files.readString(path);
                    for (String sentinel : secrets.values()) {
                        assertFalse(content.contains(sentinel), path + " leaked " + sentinel);
                    }
                }
            }
        }
    }
}
