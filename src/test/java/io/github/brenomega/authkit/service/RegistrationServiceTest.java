package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import io.github.brenomega.authkit.domain.user.dto.RegisterRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.dto.EmailPayload;
import io.github.brenomega.authkit.service.spi.QueuePublisher;

@ExtendWith(MockitoExtension.class)
class RegistrationServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private QueuePublisher<EmailPayload> emailPublisher;

    @InjectMocks
    private RegistrationService service;

    @Test
    @DisplayName("Registers user successfully, hashes password, generates tenantId and queues email")
    void registerUser_success() {
        RegisterRequest request = new RegisterRequest(
                "new@example.com", "Password123!", "Alice", null, true, true);

        when(userRepository.findByEmail("new@example.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("Password123!")).thenReturn("hashedPwd");
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));

        User user = service.registerUser(request);

        assertNotNull(user);
        assertNotNull(user.getTenantId(), "Multi-tenancy ID must be generated");
        assertFalse(user.isEmailConfirmed(), "Email must not be confirmed yet");

        verify(emailPublisher).publish(argThat(payload -> 
                payload.to().equals("new@example.com") &&
                payload.htmlBody().contains("activate?token=")
        ));
    }

    @Test
    @DisplayName("Fails registration if email is already in use")
    void registerUser_conflict() {
        RegisterRequest request = new RegisterRequest(
                "existing@example.com", "Password123!", "Alice", null, true, true);

        User existingUser = new User("existing@example.com", "pw", null, null, true, true, null);
        when(userRepository.findByEmail("existing@example.com")).thenReturn(Optional.of(existingUser));

        assertThrows(io.github.brenomega.authkit.exception.UserAlreadyExistsException.class, () -> service.registerUser(request));
    }
}
