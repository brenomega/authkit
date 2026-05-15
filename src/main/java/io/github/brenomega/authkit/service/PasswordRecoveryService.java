package io.github.brenomega.authkit.service;

import java.util.UUID;
import java.util.concurrent.Semaphore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.exception.InvalidTokenException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.infrastructure.aop.LogExecutionTime;
import io.github.brenomega.authkit.infrastructure.cache.AccountLockoutService;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.dto.EmailPayload;
import io.github.brenomega.authkit.service.spi.QueuePublisher;
import io.github.brenomega.authkit.service.spi.TokenStorage;

/**
 * Service for handling password recovery workflows (RF 2.1.3, RF 2.1.4).
 *
 * <p>Implements the "stealth" initiation strategy (DT 3.2.15) and
 * secure token-based reset with infrastructure integration.</p>
 *
 * <p><strong>Lockout Integration (DT 3.2.23):</strong> A successful password
 * reset is the <strong>only</strong> sanctioned path to clear the progressive
 * lockout counter and unlock a frozen account.</p>
 *
 * <p><strong>Session Revocation (RF 2.1.12):</strong> All active refresh tokens
 * are revoked upon password reset to force re-authentication.</p>
 *
 * @see AccountLockoutService
 */
@Service
public class PasswordRecoveryService {

    private static final Logger log = LoggerFactory.getLogger(PasswordRecoveryService.class);

    private final UserRepository userRepository;
    private final TokenStorage tokenStorage;
    private final QueuePublisher<EmailPayload> emailPublisher;
    private final PasswordEncoder passwordEncoder;
    private final AccountLockoutService lockoutService;
    private final Semaphore argon2Semaphore;

    public PasswordRecoveryService(
            UserRepository userRepository,
            TokenStorage tokenStorage,
            QueuePublisher<EmailPayload> emailPublisher,
            PasswordEncoder passwordEncoder,
            AccountLockoutService lockoutService) {
        this.userRepository = userRepository;
        this.tokenStorage = tokenStorage;
        this.emailPublisher = emailPublisher;
        this.passwordEncoder = passwordEncoder;
        this.lockoutService = lockoutService;
        
        int permits = (int) (Runtime.getRuntime().availableProcessors() * 1.5);
        this.argon2Semaphore = new Semaphore(Math.max(2, permits));
    }

    /**
     * Initiates the password recovery flow (RF 2.1.3).
     *
     * <p><strong>Stealth Strategy (DT 3.2.15):</strong> Always returns success
     * regardless of account existence to prevent enumeration.</p>
     *
     * @param email the email to send the recovery link to
     */
    @LogExecutionTime
    public void requestRecovery(String email) {
        userRepository.findByEmail(email).ifPresentOrElse(
                user -> {
                    String token = UUID.randomUUID().toString();
                    tokenStorage.storeRecoveryToken(email, token, 15); // 15 mins TTL
                    
                    String resetLink = "https://frontend.url/reset-password?token=" + token + "&email=" + email;
                    EmailPayload emailPayload = new EmailPayload(
                            email,
                            "Password Recovery",
                            "Click here to reset your password: " + resetLink
                    );
                    emailPublisher.publish(emailPayload);
                    log.info("Password recovery requested for existing user. Token generated and event published.");
                },
                () -> log.info("Password recovery requested for non-existing email: {}. Stealth response triggered.", email)
        );
    }

    /**
     * Resets the user's password using a valid token (RF 2.1.4).
     *
     * @param email       the user's email
     * @param token       the recovery token
     * @param newPassword the new password
     * @throws IllegalArgumentException if the token is invalid or expired
     */
    @Transactional
    @LogExecutionTime
    public void resetPassword(String email, String token, String newPassword) {
        if (!tokenStorage.validateRecoveryToken(email, token)) {
            log.warn("Invalid or expired password recovery token for email: {}", email);
            throw new InvalidTokenException();
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(UserNotFoundException::new);

        try {
            argon2Semaphore.acquire();
            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Interrupted during password hashing", e);
        } finally {
            argon2Semaphore.release();
        }

        tokenStorage.revokeRecoveryToken(email);

        // DT 3.2.23: Clear progressive lockout — this is the ONLY unlock path
        lockoutService.clearLockout(email);

        // RF 2.1.12: Revoke all active sessions to force re-authentication
        tokenStorage.revokeAllSessions(user.getId().toString());
        
        EmailPayload confirmation = new EmailPayload(
                email,
                "Password Changed",
                "Your password has been successfully changed."
        );
        emailPublisher.publish(confirmation);
        
        log.info("Password successfully reset for user: {}", user.getId());
    }
}
