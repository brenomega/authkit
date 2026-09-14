package io.github.brenomega.authkit;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

/** Enforces the public documentation pairing, navigation and local-link contract. */
class DocumentationContractTest {

    private static final Pattern MARKDOWN_LINK = Pattern.compile("(?<!!)\\[[^]]*]\\(([^)]+)\\)");
    private static final List<String> ENGLISH_DOCUMENTS = List.of(
            "README.md",
            "docs/README.md",
            "docs/CONFIGURATION.md",
            "docs/EMAIL_TEMPLATES.md",
            "docs/INSTALL.md",
            "docs/INTEGRATOR.md",
            "docs/OPERATIONS.md",
            "docs/RELEASING.md",
            "docs/SECURITY_MODEL.md",
            "docs/THREAT_MODEL.md",
            "docs/TRACEABILITY.md",
            "docs/USE_CASES.md",
            "docs/architecture/SYSTEM_DESIGN.md",
            "docs/proof/README.md",
            "docs/proof/performance-baselines.md",
            "docs/reference/SUPPORT_MATRIX.md",
            "docs/release/RELEASE_GATES.md");

    @Test
    void publicDocumentsHaveLanguagePairsSelectorsAndPrecedenceNotices() throws IOException {
        Path root = Path.of("").toAbsolutePath().normalize();
        for (String englishName : ENGLISH_DOCUMENTS) {
            Path english = root.resolve(englishName);
            String fileName = english.getFileName().toString();
            Path portuguese = english.resolveSibling(fileName.substring(0, fileName.length() - 3) + "-ptBR.md");

            assertThat(english).as("English document %s", englishName).exists();
            assertThat(portuguese).as("Portuguese pair for %s", englishName).exists();

            String englishText = Files.readString(english);
            String portugueseText = Files.readString(portuguese);
            String selector = "[English](" + fileName + ") | [Português (Brasil)]("
                    + portuguese.getFileName() + ")";
            assertThat(englishText).as("selector in %s", englishName).contains(selector);
            assertThat(portugueseText).as("selector in %s", portuguese).contains(selector);
            assertThat(englishText).contains("English is authoritative");
            assertThat(portugueseText).contains("O inglês é autoritativo");
        }
    }

    @Test
    void canonicalDocumentationHasNoBrokenLocalLinks() throws IOException {
        Path root = Path.of("").toAbsolutePath().normalize();
        try (Stream<Path> paths = Stream.concat(Stream.of(root.resolve("README.md"), root.resolve("README-ptBR.md")),
                Files.walk(root.resolve("docs")).filter(path -> path.toString().endsWith(".md")))) {
            for (Path document : paths.toList()) {
                Matcher matcher = MARKDOWN_LINK.matcher(Files.readString(document));
                while (matcher.find()) {
                    String target = matcher.group(1).trim();
                    int title = target.indexOf(" \"");
                    if (title >= 0) target = target.substring(0, title);
                    if (target.startsWith("<") && target.endsWith(">")) {
                        target = target.substring(1, target.length() - 1);
                    }
                    int fragment = target.indexOf('#');
                    if (fragment >= 0) target = target.substring(0, fragment);
                    int query = target.indexOf('?');
                    if (query >= 0) target = target.substring(0, query);
                    if (target.isBlank() || URI.create(target).isAbsolute() || target.startsWith("mailto:")) continue;

                    assertThat(document.getParent().resolve(target).normalize())
                            .as("link '%s' from %s", target, root.relativize(document))
                            .exists();
                }
            }
        }
    }

    @Test
    void portugueseLandingPageDoesNotFallThroughToEnglishEquivalent() throws IOException {
        String landing = Files.readString(Path.of("README-ptBR.md"));
        String bodyAfterSelector = landing.substring(landing.indexOf('\n', landing.indexOf('\n') + 1) + 1);
        assertThat(bodyAfterSelector).doesNotContain("docs/SECURITY_MODEL.md")
                .doesNotContain("docs/INSTALL.md")
                .doesNotContain("docs/OPERATIONS.md")
                .doesNotContain("docs/CONFIGURATION.md");
    }
}
