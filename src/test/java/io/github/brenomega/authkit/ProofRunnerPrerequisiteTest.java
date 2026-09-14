package io.github.brenomega.authkit;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests the evidence runner's exit semantics, not the product/provider gates. */
class ProofRunnerPrerequisiteTest {
    @TempDir Path root;

    @Test
    void missingRequiredEnvironmentIsNonzeroUnlessExplicitDeveloperMode() throws Exception {
        var command = "source testing/proof/smoke/lib.sh; unset AUTHKIT_MISSING_TEST_INPUT; skip_if_missing AUTHKIT_MISSING_TEST_INPUT";
        var release = new ProcessBuilder("bash", "-c", command).redirectErrorStream(true);
        release.environment().put("AUTHKIT_PROOF_MODE", "release");
        var process = release.start();
        String output = new String(process.getInputStream().readAllBytes());
        assertNotEquals(0, process.waitFor()); assertTrue(output.contains("FAIL:"));
        release.environment().put("AUTHKIT_PROOF_MODE", "development");
        process = release.start(); output = new String(process.getInputStream().readAllBytes());
        assertEquals(0, process.waitFor()); assertTrue(output.contains("SKIP (development mode only)"));
    }

    @Test
    void missingNegativeCorpusAndFailedSnapshotCannotProduceGreenSummary() throws Exception {
        Path proof = Files.createDirectories(root.resolve("testing/proof"));
        Files.copy(Path.of("testing/proof/run-proof.sh"), proof.resolve("run-proof.sh"));
        Path smoke = Files.createDirectories(proof.resolve("smoke"));
        for (String script : List.of("collect-prometheus-snapshot", "health-and-metrics",
                "register-confirm-login-refresh-logout", "password-recovery-reset", "mfa-login",
                "session-list-revoke", "oauth-code-token-userinfo")) {
            Path file = smoke.resolve(script + ".sh");
            Files.writeString(file, "#!/usr/bin/env bash\nexit 0\n");
            assertTrue(file.toFile().setExecutable(true));
        }
        var builder = new ProcessBuilder("bash", proof.resolve("run-proof.sh").toString(),
                "--tier", "prerequisite-test", "--backend", "redis", "--email-provider", "smtp")
                .redirectErrorStream(true);
        builder.environment().put("AUTHKIT_BASE_URL", "http://localhost:1");
        builder.environment().put("AUTHKIT_PROOF_MODE", "development");
        var process = builder.start();
        String output = new String(process.getInputStream().readAllBytes());
        assertEquals(1, process.waitFor());
        assertTrue(output.contains("FAIL: target/contract-fixtures is missing"));
        try (var paths = Files.walk(root.resolve("docs/proof/reports"))) {
            Path summary = paths.filter(path -> path.getFileName().toString().equals("run-summary.txt")).findFirst().orElseThrow();
            assertTrue(Files.readString(summary).contains("exit_status=1"));
        }
        Files.writeString(smoke.resolve("collect-prometheus-snapshot.sh"), "#!/usr/bin/env bash\nexit 7\n");
        process = builder.start(); process.getInputStream().readAllBytes();
        assertEquals(7, process.waitFor());
    }
}
