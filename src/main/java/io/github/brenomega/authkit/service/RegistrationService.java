package io.github.brenomega.authkit.service;

import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.domain.user.dto.RegisterRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.EmailNormalizer;
import io.github.brenomega.authkit.exception.UserAlreadyExistsException;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.dto.EmailPayload;
import io.github.brenomega.authkit.service.spi.QueuePublisher;
import io.github.brenomega.authkit.infrastructure.aop.LogExecutionTime;

/**
 * Service handling the user registration and activation flow.
 */
@Service
public class RegistrationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final QueuePublisher<EmailPayload> emailPublisher;

    public RegistrationService(UserRepository userRepository,
                               PasswordEncoder passwordEncoder,
                               QueuePublisher<EmailPayload> emailPublisher) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailPublisher = emailPublisher;
    }

    /**
     * Registers a new user with multi-tenancy and async email activation.
     *
     * @param request defined by the DTO whitelist
     * @return the saved entity
     */
    @Transactional
    @LogExecutionTime
    public User registerUser(RegisterRequest request) {
        String email = EmailNormalizer.normalize(request.email());

        if (userRepository.findByEmail(email).isPresent()) {
            throw new UserAlreadyExistsException("Email already in use");
        }

        String hashedPassword = passwordEncoder.encode(request.password());
        String confirmationToken = UUID.randomUUID().toString();

        User user = new User(
                email,
                hashedPassword,
                null,
                null,
                request.termsAccepted(),
                request.privacyPolicyAccepted(),
                confirmationToken
        );

        try {
            user = userRepository.save(user);
        } catch (DataIntegrityViolationException e) {
            throw new UserAlreadyExistsException("Email already in use");
        }

        // Async activation trigger
        String activationUrl = "https://authkit.io/activate?token=" + confirmationToken;
        EmailPayload payload = new EmailPayload(
                user.getEmail(),
                "Welcome to AuthKit - Activate your account",
                "<p>Click <a href='" + activationUrl + "'>here</a> to activate your account.</p>"
        );
        
        emailPublisher.publish(payload);

        return user;
    }
}
