package io.github.brenomega.authkit.infrastructure.persistence.securityeffects;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.EmailNormalizer;
import io.github.brenomega.authkit.infrastructure.audit.AuditDigestService;
import io.github.brenomega.authkit.infrastructure.persistence.AfterCommitActions;
import io.github.brenomega.authkit.repository.UserRepository;

/** Commits invalidation state and external reconciliation intent in one SQL transaction. */
@Service
public class SecurityEffectService {

    private final SecurityEffectRepository repository;
    private final SecurityEffectProcessor processor;
    private final AuditDigestService auditDigestService;
    private final UserRepository userRepository;

    public SecurityEffectService(SecurityEffectRepository repository,
                                 SecurityEffectProcessor processor,
                                 AuditDigestService auditDigestService,
                                 UserRepository userRepository) {
        this.repository = repository;
        this.processor = processor;
        this.auditDigestService = auditDigestService;
        this.userRepository = userRepository;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public long invalidateSessions(User user, String preservedSessionJti) {
        long targetVersion = user.invalidateSessions(preservedSessionJti);
        // A prior bulk DML operation may have cleared the persistence context
        // and detached this user. Merge and flush the durable boundary here so
        // the SQL version and its outbox intent cannot diverge at commit.
        userRepository.saveAndFlush(user);
        SecurityEffectTask task = repository.save(SecurityEffectTask.revokeStaleSessions(
                user.getId(), targetVersion, preservedSessionJti));
        AfterCommitActions.run(() -> processor.processOne(task.getId()));
        return targetVersion;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void revokeRecoveryToken(String email) {
        String digest = auditDigestService.hmacHex(EmailNormalizer.normalize(email));
        SecurityEffectTask task = repository.save(SecurityEffectTask.revokeRecoveryToken(digest));
        AfterCommitActions.run(() -> processor.processOne(task.getId()));
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void activateRecoveryToken(User user, String rawToken, long ttlMinutes, java.util.UUID messageId) {
        SecurityEffectTask task = repository.save(SecurityEffectTask.activateRecoveryToken(
                user.getId(), user.getSecurityVersion(),
                auditDigestService.hmacHex(EmailNormalizer.normalize(user.getEmail())),
                io.github.brenomega.authkit.domain.user.util.TokenHasher.sha256Hex(rawToken),
                java.time.Instant.now().plusSeconds(Math.multiplyExact(ttlMinutes, 60)), messageId));
        AfterCommitActions.run(() -> processor.processOne(task.getId()));
    }
}
