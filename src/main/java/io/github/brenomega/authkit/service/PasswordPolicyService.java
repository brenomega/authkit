package io.github.brenomega.authkit.service;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.springframework.data.domain.PageRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.domain.user.entity.PasswordHistoryEntry;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.EmailNormalizer;
import io.github.brenomega.authkit.exception.AuthenticationCapacityExceededException;
import io.github.brenomega.authkit.exception.WeakPasswordException;
import io.github.brenomega.authkit.infrastructure.security.Argon2ConcurrencyLimiter;
import io.github.brenomega.authkit.repository.PasswordHistoryRepository;
import io.github.brenomega.authkit.service.spi.CompromisedPasswordChecker;

@Service
public class PasswordPolicyService {

    private static final int HISTORY_DEPTH = 5;
    private static final Set<String> COMMON_PASSWORDS = Set.of(
            "password", "password1", "password12", "password123", "password1234",
            "12345678", "123456789", "1234567890", "qwerty123", "qwertyuiop",
            "letmein123", "welcome123", "admin1234", "administrator", "iloveyou",
            "authkit123", "changeme123", "senha12345", "password@123", "passw0rd");

    private final PasswordHistoryRepository passwordHistoryRepository;
    private final PasswordEncoder passwordEncoder;
    private final Argon2ConcurrencyLimiter argon2Limiter;
    private final CompromisedPasswordChecker compromisedPasswordChecker;

    public PasswordPolicyService(PasswordHistoryRepository passwordHistoryRepository,
                                 PasswordEncoder passwordEncoder,
                                 Argon2ConcurrencyLimiter argon2Limiter) {
        this(passwordHistoryRepository, passwordEncoder, argon2Limiter, ignored -> false);
    }

    @Autowired
    public PasswordPolicyService(PasswordHistoryRepository passwordHistoryRepository,
                                 PasswordEncoder passwordEncoder,
                                 Argon2ConcurrencyLimiter argon2Limiter,
                                 CompromisedPasswordChecker compromisedPasswordChecker) {
        this.passwordHistoryRepository = passwordHistoryRepository;
        this.passwordEncoder = passwordEncoder;
        this.argon2Limiter = argon2Limiter;
        this.compromisedPasswordChecker = compromisedPasswordChecker;
    }

    @Transactional(readOnly = true)
    public void validateForRegistration(String email, String rawPassword) {
        validateComposition(email, null, rawPassword);
        rejectIfCompromised(rawPassword);
    }

    @Transactional(readOnly = true)
    public void validateForUser(User user, String rawPassword) {
        validateComposition(user.getEmail(), user.getName(), rawPassword);
        rejectIfCompromised(rawPassword);
        rejectIfMatches(rawPassword, user.getPassword());
        List<PasswordHistoryEntry> recent = passwordHistoryRepository.findByUserIdOrderByCreatedAtDesc(
                user.getId(),
                PageRequest.of(0, HISTORY_DEPTH));
        for (PasswordHistoryEntry entry : recent) {
            rejectIfMatches(rawPassword, entry.getPasswordHash());
        }
    }

    @Transactional
    public void recordCurrentPassword(User user) {
        passwordHistoryRepository.save(new PasswordHistoryEntry(user.getId(), user.getPassword(), Instant.now()));
    }

    private void validateComposition(String email, String name, String rawPassword) {
        if (rawPassword == null || rawPassword.length() < 8 || rawPassword.length() > 128) {
            throw new WeakPasswordException();
        }
        String lower = rawPassword.toLowerCase(Locale.ROOT);
        if (COMMON_PASSWORDS.contains(lower) || containsRun(lower) || containsIdentity(lower, email, name)) {
            throw new WeakPasswordException();
        }
        boolean hasLower = rawPassword.chars().anyMatch(Character::isLowerCase);
        boolean hasUpper = rawPassword.chars().anyMatch(Character::isUpperCase);
        boolean hasDigit = rawPassword.chars().anyMatch(Character::isDigit);
        boolean hasSymbol = rawPassword.chars().anyMatch(ch -> !Character.isLetterOrDigit(ch));
        if ((hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSymbol ? 1 : 0) < 3) {
            throw new WeakPasswordException();
        }
    }

    private void rejectIfMatches(String rawPassword, String encodedPassword) {
        boolean acquired = argon2Limiter.tryAcquire();
        if (!acquired) {
            throw new AuthenticationCapacityExceededException();
        }
        try {
            if (passwordEncoder.matches(rawPassword, encodedPassword)) {
                throw new WeakPasswordException();
            }
        } finally {
            argon2Limiter.release();
        }
    }

    private void rejectIfCompromised(String rawPassword) {
        if (compromisedPasswordChecker.isCompromised(rawPassword)) {
            throw new WeakPasswordException();
        }
    }

    private boolean containsIdentity(String lowerPassword, String email, String name) {
        String normalizedEmail = email == null ? "" : EmailNormalizer.normalize(email);
        int at = normalizedEmail.indexOf('@');
        if (at > 2 && lowerPassword.contains(normalizedEmail.substring(0, at).toLowerCase(Locale.ROOT))) {
            return true;
        }
        if (name == null || name.isBlank()) {
            return false;
        }
        return java.util.Arrays.stream(name.toLowerCase(Locale.ROOT).split("[^a-z0-9]+"))
                .filter(part -> part.length() >= 3)
                .anyMatch(lowerPassword::contains);
    }

    private boolean containsRun(String lowerPassword) {
        return lowerPassword.contains("abcdef")
                || lowerPassword.contains("qwerty")
                || lowerPassword.contains("123456")
                || lowerPassword.contains("654321");
    }
}
