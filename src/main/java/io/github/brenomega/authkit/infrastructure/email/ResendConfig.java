package io.github.brenomega.authkit.infrastructure.email;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

/**
 * Configuration for the Resend API HTTP client.
 */
@Configuration
public class ResendConfig {

    private final String resendApiKey;

    /**
     * @param resendApiKey injected from RESEND_API_KEY environment variable
     */
    public ResendConfig(@Value("${resend.api.key}") String resendApiKey) {
        this.resendApiKey = resendApiKey;
    }

    /**
     * Creates a {@link RestClient} customized with the Resend Base URL
     * and the static Authorization header.
     *
     * @return the ready-to-use HTTP client
     */
    @Bean
    public RestClient resendRestClient() {
        return RestClient.builder()
                .baseUrl("https://api.resend.com/emails")
                .defaultHeader("Authorization", "Bearer " + resendApiKey)
                .build();
    }
}
