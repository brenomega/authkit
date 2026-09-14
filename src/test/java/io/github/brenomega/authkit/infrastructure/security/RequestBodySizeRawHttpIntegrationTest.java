package io.github.brenomega.authkit.infrastructure.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;

/** Exercises fixed-length and HTTP/1.1 chunked DELETE bodies through the real servlet stack. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class RequestBodySizeRawHttpIntegrationTest {

    private static final int LIMIT = 65_536;

    @LocalServerPort
    private int port;

    private final HttpClient client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    @Test
    void oversizedFixedAndChunkedDeleteReturn413WhileBoundaryPassesTheSizeFilter() throws Exception {
        byte[] oversized = "x".repeat(LIMIT + 1).getBytes(StandardCharsets.UTF_8);
        HttpResponse<String> fixed = send(HttpRequest.BodyPublishers.ofByteArray(oversized));
        assertEquals(413, fixed.statusCode());

        HttpResponse<String> chunked = send(HttpRequest.BodyPublishers.ofInputStream(
                () -> new ByteArrayInputStream(oversized)));
        assertEquals(413, chunked.statusCode());

        HttpResponse<String> boundary = send(HttpRequest.BodyPublishers.ofByteArray(
                "x".repeat(LIMIT).getBytes(StandardCharsets.UTF_8)));
        assertNotEquals(413, boundary.statusCode());
        assertEquals(401, boundary.statusCode(), "boundary body must reach authentication");
    }

    private HttpResponse<String> send(HttpRequest.BodyPublisher body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(
                        URI.create("http://127.0.0.1:" + port + "/api/v1/users/me"))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .method("DELETE", body)
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
