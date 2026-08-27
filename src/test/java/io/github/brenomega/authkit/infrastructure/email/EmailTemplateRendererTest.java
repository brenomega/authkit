package io.github.brenomega.authkit.infrastructure.email;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EmailTemplateRendererTest {

    @Test
    void loadsEveryOperatorTemplateAndEscapesActionUrl() {
        var renderer = new EmailTemplateRenderer("src/test/resources/email-templates", 65_536);
        renderer.loadAndValidate();

        var payload = renderer.render(EmailTemplateId.PASSWORD_RECOVERY, "user@example.test",
                Map.of("action_url", "https://app.example/reset#token=a&email=b@example.test"));
        assertTrue(payload.htmlBody().contains("#token=a&amp;email=b@example.test"));
        assertTrue(payload.subject().contains("test"));
    }

    @Test
    void rejectsExecutableOperatorHtml(@TempDir Path directory) throws Exception {
        for (EmailTemplateId id : EmailTemplateId.values()) {
            Files.writeString(directory.resolve(id.fileStem() + ".subject.txt"), "Subject");
            Files.writeString(directory.resolve(id.fileStem() + ".body.html"),
                    id.actionUrlRequired() ? "<a href=\"{{action_url}}\">Action</a>" : "<p>Notice</p>");
        }
        Files.writeString(directory.resolve("password-changed.body.html"), "<script>alert(1)</script>");
        var renderer = new EmailTemplateRenderer(directory.toString(), 65_536);
        assertThrows(IllegalStateException.class, renderer::loadAndValidate);
    }
}
