package io.github.brenomega.authkit.infrastructure.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Configuration for password hashing algorithms.
 */
@Configuration
public class PasswordConfig {

    /**
     * Configures Argon2id as the official password encoder (DT 3.2.1).
     *
     * <p>Algorithm parameters are explicitly set as per security requirements:
     * t=3 (iterations), m=65536 (memory footprint), p=2 (parallelism).</p>
     *
     * @return the configured Argon2 password encoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        int saltLength = 16;
        int hashLength = 32;
        int parallelism = 2; // p
        int memory = 65536;  // m
        int iterations = 3;  // t

        return new Argon2PasswordEncoder(
                saltLength, hashLength, parallelism, memory, iterations);
    }
}
