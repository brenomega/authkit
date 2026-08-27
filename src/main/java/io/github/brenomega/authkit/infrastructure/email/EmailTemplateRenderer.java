package io.github.brenomega.authkit.infrastructure.email;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.EnumMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.github.brenomega.authkit.service.spi.EmailPayload;
import jakarta.annotation.PostConstruct;

/** Loads operator-owned templates and performs only escaped variable substitution. */
@Component
public class EmailTemplateRenderer {
    private static final Pattern PLACEHOLDER = Pattern.compile("\\{\\{([a-z_]+)}}");
    private static final Pattern UNSAFE_HTML = Pattern.compile(
            "(?i)<\\s*script|javascript\\s*:|on[a-z]+\\s*=|<\\s*(iframe|object|embed)");
    private static final int MAX_SUBJECT_BYTES = 1024;

    private final String configuredDirectory;
    private final int maxBodyBytes;
    private final Map<EmailTemplateId, Template> templates = new EnumMap<>(EmailTemplateId.class);

    public EmailTemplateRenderer(
            @Value("${authkit.auth.email-templates.directory:}") String configuredDirectory,
            @Value("${authkit.auth.email-templates.max-body-bytes:65536}") int maxBodyBytes) {
        this.configuredDirectory = configuredDirectory;
        this.maxBodyBytes = maxBodyBytes;
    }

    @PostConstruct
    void loadAndValidate() {
        if (configuredDirectory == null || configuredDirectory.isBlank()) {
            throw new IllegalStateException("Operator email template directory is required");
        }
        try {
            Path root = Path.of(configuredDirectory).toRealPath();
            if (!Files.isDirectory(root)) {
                throw new IllegalStateException("Operator email template path is not a directory");
            }
            for (EmailTemplateId id : EmailTemplateId.values()) {
                String subject = readBounded(root, id.fileStem() + ".subject.txt", MAX_SUBJECT_BYTES).strip();
                String body = readBounded(root, id.fileStem() + ".body.html", maxBodyBytes);
                validate(id, subject, body);
                templates.put(id, new Template(subject, body));
            }
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to load operator email templates", ex);
        }
    }

    public EmailPayload render(EmailTemplateId id, String recipient, Map<String, String> variables) {
        Template template = templates.get(id);
        if (template == null) {
            throw new IllegalStateException("Email template was not initialized: " + id);
        }
        if (id.actionUrlRequired() && (variables.get("action_url") == null || variables.get("action_url").isBlank())) {
            throw new IllegalArgumentException("action_url is required for " + id);
        }
        String subject = substitute(template.subject(), variables, false);
        String body = substitute(template.body(), variables, true);
        return new EmailPayload(recipient, subject, body);
    }

    private String readBounded(Path root, String name, int maxBytes) throws IOException {
        Path candidate = root.resolve(name).normalize();
        Path real = candidate.toRealPath();
        if (!real.startsWith(root) || !Files.isRegularFile(real)) {
            throw new IllegalStateException("Invalid email template file: " + name);
        }
        long size = Files.size(real);
        if (size < 1 || size > maxBytes) {
            throw new IllegalStateException("Email template file has invalid size: " + name);
        }
        return Files.readString(real, StandardCharsets.UTF_8);
    }

    private void validate(EmailTemplateId id, String subject, String body) {
        if (subject.isBlank() || subject.length() > 255 || subject.contains("\r") || subject.contains("\n")) {
            throw new IllegalStateException("Invalid subject template: " + id);
        }
        if (body.isBlank() || UNSAFE_HTML.matcher(body).find()) {
            throw new IllegalStateException("Unsafe or empty body template: " + id);
        }
        validatePlaceholders(subject, id);
        validatePlaceholders(body, id);
        if (id.actionUrlRequired() && !body.contains("{{action_url}}")) {
            throw new IllegalStateException("Template must contain {{action_url}}: " + id);
        }
    }

    private void validatePlaceholders(String value, EmailTemplateId id) {
        Matcher matcher = PLACEHOLDER.matcher(value);
        while (matcher.find()) {
            if (!"action_url".equals(matcher.group(1))) {
                throw new IllegalStateException("Unsupported placeholder in template " + id);
            }
        }
        String withoutKnown = value.replace("{{action_url}}", "");
        if (withoutKnown.contains("{{") || withoutKnown.contains("}}")) {
            throw new IllegalStateException("Malformed template expression in " + id);
        }
    }

    private String substitute(String source, Map<String, String> variables, boolean html) {
        Matcher matcher = PLACEHOLDER.matcher(source);
        StringBuffer result = new StringBuffer();
        while (matcher.find()) {
            String raw = variables.get(matcher.group(1));
            if (raw == null) {
                throw new IllegalArgumentException("Missing email template variable: " + matcher.group(1));
            }
            matcher.appendReplacement(result, Matcher.quoteReplacement(html ? escapeHtml(raw) : raw));
        }
        matcher.appendTail(result);
        return result.toString();
    }

    private String escapeHtml(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private record Template(String subject, String body) {}
}
