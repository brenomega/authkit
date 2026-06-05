package io.github.brenomega.authkit.infrastructure.security;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import org.springframework.stereotype.Component;

/** HIBP range API client that sends only a five-character SHA-1 prefix. */
@Component
public class HttpHibpRangeClient implements HibpRangeClient {

    private static final URI RANGE_API = URI.create("https://api.pwnedpasswords.com/range/");

    private final HttpClient httpClient;
    private final Duration readTimeout;

    public HttpHibpRangeClient(AuthProperties authProperties) {
        AuthProperties.Password config = authProperties.getPassword();
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(config.getHibpConnectTimeoutMs()))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        this.readTimeout = Duration.ofMillis(config.getHibpReadTimeoutMs());
    }

    @Override
    public String fetchRange(String sha1Prefix) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(RANGE_API.resolve(sha1Prefix))
                .timeout(readTimeout)
                .header("Add-Padding", "true")
                .header("User-Agent", "AuthKit-PwnedPassword-Check")
                .GET()
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("HIBP range API returned a non-success status");
        }
        return response.body();
    }
}
