package io.github.brenomega.authkit.infrastructure.bootstrap;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import io.github.brenomega.authkit.domain.user.dto.BootstrapAdminRequest;
import io.github.brenomega.authkit.service.BootstrapAdminService;

/**
 * Runs the explicitly enabled one-shot platform-administrator bootstrap process.
 * Secrets are accepted only through bounded standard input or a mounted file, never
 * command-line arguments. After validation and atomic bootstrap, the application
 * context closes so this mode cannot continue serving ordinary traffic.
 */
@Component
@Order(Ordered.LOWEST_PRECEDENCE)
@ConditionalOnProperty(name = "authkit.bootstrap.enabled", havingValue = "true")
public class BootstrapAdminRunner implements ApplicationRunner {

    private static final int MAX_INPUT_BYTES = 16 * 1024;

    private final ObjectMapper objectMapper;
    private final Validator validator;
    private final BootstrapAdminService bootstrapAdminService;
    private final ConfigurableApplicationContext applicationContext;
    private final String inputFile;

    public BootstrapAdminRunner(ObjectMapper objectMapper,
                                Validator validator,
                                BootstrapAdminService bootstrapAdminService,
                                ConfigurableApplicationContext applicationContext,
                                @Value("${authkit.bootstrap.input-file:}") String inputFile) {
        this.objectMapper = objectMapper;
        this.validator = validator;
        this.bootstrapAdminService = bootstrapAdminService;
        this.applicationContext = applicationContext;
        this.inputFile = inputFile;
    }

    /**
     * Reads and validates bootstrap input, delegates the singleton transition, and terminates the process context.
     *
     * @throws Exception if input, validation, or bootstrap persistence fails
     */
    @SuppressWarnings("null")
    @Override
    public void run(ApplicationArguments args) throws Exception {
        if (args.containsOption("password") || args.containsOption("secret") || !args.getNonOptionArgs().isEmpty()) {
            throw new IllegalArgumentException("Bootstrap secrets are accepted only through stdin or a mounted file");
        }
        BootstrapAdminRequest request = readRequest();
        var violations = validator.validate(request);
        if (!violations.isEmpty()) {
            String fields = violations.stream()
                    .map(ConstraintViolation::getPropertyPath)
                    .map(Object::toString)
                    .sorted()
                    .distinct()
                    .reduce((left, right) -> left + ", " + right)
                    .orElse("input");
            throw new IllegalArgumentException("Invalid bootstrap input fields: " + fields);
        }

        bootstrapAdminService.bootstrap(request);
        System.out.println("Platform administrator bootstrap completed; enroll local MFA or " +
            "a passkey before administrative mutations.");
        applicationContext.close();
    }

    private BootstrapAdminRequest readRequest() throws IOException {
        byte[] bytes;
        if (inputFile != null && !inputFile.isBlank()) {
            Path path = Path.of(inputFile);
            long size = Files.size(path);
            if (size > MAX_INPUT_BYTES) {
                throw new IllegalArgumentException("Bootstrap input exceeds the maximum size");
            }
            bytes = Files.readAllBytes(path);
        } else {
            bytes = System.in.readNBytes(MAX_INPUT_BYTES + 1);
            if (bytes.length > MAX_INPUT_BYTES) {
                throw new IllegalArgumentException("Bootstrap input exceeds the maximum size");
            }
        }
        if (bytes.length == 0) {
            throw new IllegalArgumentException("Bootstrap input is required on stdin or through " +
                "AUTHKIT_BOOTSTRAP_INPUT_FILE");
        }
        return objectMapper.readValue(bytes, BootstrapAdminRequest.class);
    }
}
