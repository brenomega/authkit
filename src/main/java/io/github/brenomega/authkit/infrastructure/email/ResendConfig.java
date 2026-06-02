package io.github.brenomega.authkit.infrastructure.email;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import io.github.brenomega.authkit.infrastructure.security.AuthProperties;

/**
 * Configuration for the Resend API HTTP client.
 */
@Configuration
@ConditionalOnProperty(prefix = "authkit.auth.email-provider", name = "type", havingValue = "resend", matchIfMissing = true)
public class ResendConfig {

    private final String resendApiKey;
    private final AuthProperties authProperties;

    /**
     * @param resendApiKey injected from RESEND_API_KEY environment variable
     */
    public ResendConfig(@Value("${resend.api.key}") String resendApiKey,
                        AuthProperties authProperties) {
        this.resendApiKey = resendApiKey;
        this.authProperties = authProperties;
    }

    /**
     * Creates a {@link RestClient} customized with the Resend Base URL
     * and the static Authorization header.
     *
     * @return the ready-to-use HTTP client
     */
    @Bean
    public RestClient resendRestClient() {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(authProperties.getEmailProvider().getConnectTimeoutMs());
        requestFactory.setReadTimeout(authProperties.getEmailProvider().getReadTimeoutMs());
        return RestClient.builder()
                .requestFactory(requestFactory)
                .baseUrl("https://api.resend.com/emails")
                .defaultHeader("Authorization", "Bearer " + resendApiKey)
                .build();
    }
}
