package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.domain.user.dto.BootstrapAdminRequest;
import io.github.brenomega.authkit.domain.user.entity.BootstrapState;
import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.infrastructure.audit.ConsentEventRepository;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventRepository;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.repository.BootstrapStateRepository;
import io.github.brenomega.authkit.repository.UserRepository;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class BootstrapAdminServiceTest {

    @Autowired private BootstrapAdminService bootstrapAdminService;
    @Autowired private BootstrapStateRepository bootstrapStateRepository;
    @Autowired private UserRepository userRepository;
    @Autowired private SecurityEventRepository securityEventRepository;
    @Autowired private ConsentEventRepository consentEventRepository;

    @Test
    void createsVerifiedFirstAdminWithConsentAndCriticalAuditThenRejectsRepeat() {
        bootstrapStateRepository.save(new BootstrapState(BootstrapState.SINGLETON_ID));
        BootstrapAdminRequest request = request("first-admin@example.test");

        var admin = bootstrapAdminService.bootstrap(request);

        assertEquals(Role.PLATFORM_ADMIN, admin.getRole());
        assertTrue(admin.isEmailConfirmed());
        assertTrue(admin.isActive());
        assertFalse(admin.getPassword().contains(request.password()));
        assertEquals(1, userRepository.countByRole(Role.PLATFORM_ADMIN));
        assertEquals(1, consentEventRepository.findByUserIdOrderByAcceptedAtDesc(admin.getId()).size());
        var events = securityEventRepository.findByTargetUserIdOrderByOccurredAtDesc(admin.getId());
        assertEquals(1, events.size());
        assertEquals(SecurityEventType.BOOTSTRAP, events.getFirst().getEventType());
        assertEquals(SecurityEventSeverity.CRITICAL, events.getFirst().getSeverity());
        assertTrue(bootstrapStateRepository.findById(BootstrapState.SINGLETON_ID).orElseThrow().isCompleted());

        assertThrows(IllegalStateException.class,
                () -> bootstrapAdminService.bootstrap(request("second-admin@example.test")));
        assertEquals(1, userRepository.countByRole(Role.PLATFORM_ADMIN));
    }

    private BootstrapAdminRequest request(String email) {
        return new BootstrapAdminRequest(
                email,
                "BootstrapRiver73!",
                "Initial Administrator",
                true,
                true);
    }
}
