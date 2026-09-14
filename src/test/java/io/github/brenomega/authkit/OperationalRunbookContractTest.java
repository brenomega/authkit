package io.github.brenomega.authkit;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

class OperationalRunbookContractTest {

    @Test
    void postgresRestoreDefaultTracksLatestFlywayMigration() throws Exception {
        Pattern migration = Pattern.compile("V(\\d+)__.+\\.sql");
        int latest;
        try (var files = Files.list(Path.of("src/main/resources/db/migration"))) {
            latest = files.map(path -> migration.matcher(path.getFileName().toString()))
                    .filter(Matcher::matches)
                    .mapToInt(matcher -> Integer.parseInt(matcher.group(1)))
                    .max()
                    .orElseThrow();
        }

        String restoreScript = Files.readString(Path.of("deploy/scripts/restore-postgres-check.sh"));
        Matcher configured = Pattern.compile("AUTHKIT_EXPECTED_FLYWAY_VERSION:-([0-9]+)")
                .matcher(restoreScript);
        assertTrue(configured.find(), "restore check must declare a default expected Flyway version");
        assertEquals(latest, Integer.parseInt(configured.group(1)),
                "restore check default must track the latest packaged migration");
    }

    @SuppressWarnings("unchecked")
    @Test
    void everyCriticalPrometheusAlertMapsToAnExistingRunbook() throws Exception {
        Path rulesPath = Path.of("k8s/06-prometheus-rules.yaml");
        Map<String, Object> document;
        try (InputStream input = Files.newInputStream(rulesPath)) {
            document = new Yaml().load(input);
        }
        Map<String, Object> spec = (Map<String, Object>) document.get("spec");
        List<Map<String, Object>> groups = (List<Map<String, Object>>) spec.get("groups");
        var required = new java.util.HashSet<>(List.of("AuthKitFailedLoginSpike",
                "AuthKitGlobalRateLimiterRedisDegraded", "AuthKitKeyLifecycleFailure",
                "AuthKitRedisDegradation", "AuthKitAuditFailClosed", "AuthKitEmailDeadMessages",
                "AuthKitDatabasePoolWaitSustained", "AuthKitSchedulerFailure", "AuthKitKeyRotationStalled"));
        for (Map<String, Object> group : groups) {
            for (Map<String, Object> rule : (List<Map<String, Object>>) group.get("rules")) {
                Map<String, Object> labels = (Map<String, Object>) rule.get("labels");
                if (!"critical".equals(labels.get("severity"))) {
                    continue;
                }
                required.remove(rule.get("alert"));
                Map<String, Object> annotations = (Map<String, Object>) rule.get("annotations");
                String runbook = (String) annotations.get("runbook_url");
                assertNotNull(runbook, () -> rule.get("alert") + " has no runbook_url");
                assertTrue(Files.isRegularFile(Path.of(runbook)),
                        () -> rule.get("alert") + " references missing " + runbook);
            }
        }
        assertTrue(required.isEmpty(), () -> "Missing normative critical alert families: " + required);
    }
}
