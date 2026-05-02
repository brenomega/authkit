package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import io.github.brenomega.authkit.domain.user.dto.PasswordChangeRequest;
import io.github.brenomega.authkit.domain.user.dto.ProfileUpdateRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.exception.AccountLockedException;
import io.github.brenomega.authkit.exception.InvalidCredentialsException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;
import org.springframework.security.crypto.password.PasswordEncoder;
import io.github.brenomega.authkit.infrastructure.cache.AccountLockoutService;

/**
 * Unit tests for ProfileService (DT 3.4.5).
 * Validates RF 2.1.6, RF 2.1.7, RF 2.1.8, IDOR protection (DT 3.2.24),
 * and lockout enforcement on management endpoints (DT 3.2.23).
 */
class ProfileServiceTest {

    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private TokenStorage tokenStorage;
    private AccountLockoutService lockoutService;
    private ProfileService profileService;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        passwordEncoder = mock(PasswordEncoder.class);
        tokenStorage = mock(TokenStorage.class);
        lockoutService = mock(AccountLockoutService.class);
        profileService = new ProfileService(userRepository, passwordEncoder, tokenStorage, lockoutService);
    }

    /**
     * RF 2.1.7 — Password Change: Confirms successful reset when current password is valid.
     */
    @Test
    @DisplayName("Password: Successful change revokes other sessions")
    void changePassword_Success() {
        String userId = "user-id";
        String currentJti = "current-jti";
        User user = mock(User.class);
        when(user.getPassword()).thenReturn("old-hashed");
        when(user.getEmail()).thenReturn("test@example.com");

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(lockoutService.isLocked("test@example.com")).thenReturn(false);
        when(passwordEncoder.matches("old-pass", "old-hashed")).thenReturn(true);
        when(passwordEncoder.encode("new-pass")).thenReturn("new-hashed");

        profileService.changePassword(userId, new PasswordChangeRequest("old-pass", "new-pass"), currentJti);

        verify(user).setPassword("new-hashed");
        verify(userRepository).save(user);
        verify(tokenStorage).revokeOtherSessions(userId, currentJti);
    }

    /**
     * RF 2.1.7 — Password Security: Confirms failure when current password is invalid.
     */
    @Test
    @DisplayName("Password: Change fails with invalid current password")
    void changePassword_InvalidCurrent_ThrowsException() {
        String userId = "user-id";
        User user = mock(User.class);
        when(user.getPassword()).thenReturn("hashed");
        when(user.getEmail()).thenReturn("test@example.com");

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(lockoutService.isLocked("test@example.com")).thenReturn(false);
        when(passwordEncoder.matches("wrong", "hashed")).thenReturn(false);

        assertThrows(InvalidCredentialsException.class, () -> 
            profileService.changePassword(userId, new PasswordChangeRequest("wrong", "new"), "jti"));
    }

    /**
     * DT 3.2.23 — Lockout Enforcement: Confirms password change is BLOCKED when account is locked.
     */
    @Test
    @DisplayName("Password: Change blocked when account is locked (DT 3.2.23)")
    void changePassword_LockedAccount_Throws403() {
        String userId = "user-id";
        User user = mock(User.class);
        when(user.getEmail()).thenReturn("locked@example.com");

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(lockoutService.isLocked("locked@example.com")).thenReturn(true);

        assertThrows(AccountLockedException.class, () -> 
            profileService.changePassword(userId, new PasswordChangeRequest("pass", "new"), "jti"));
        
        // Verify that password check is never reached
        verify(passwordEncoder, never()).matches(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
    }

    /**
     * DT 3.2.23 — Lockout Enforcement: Confirms session revocation is BLOCKED when account is locked.
     */
    @Test
    @DisplayName("Session: Revocation blocked when account is locked (DT 3.2.23)")
    void revokeSession_LockedAccount_Throws403() {
        String userId = "user-id";
        User user = mock(User.class);
        when(user.getEmail()).thenReturn("locked@example.com");

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(lockoutService.isLocked("locked@example.com")).thenReturn(true);

        assertThrows(AccountLockedException.class, () -> 
            profileService.revokeSession(userId, "target-jti"));
        
        // Verify that token revocation is never reached
        verify(tokenStorage, never()).revokeSession(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
    }

    /**
     * RF 2.1.8 — Session Management: Confirms individual revocation when not locked.
     */
    @Test
    @DisplayName("Session: Specific session revocation succeeds when not locked")
    void revokeSession_CallsStorage() {
        String userId = "user-id";
        User user = mock(User.class);
        when(user.getEmail()).thenReturn("test@example.com");

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(lockoutService.isLocked("test@example.com")).thenReturn(false);

        profileService.revokeSession(userId, "target-jti");
        verify(tokenStorage).revokeSession(userId, "target-jti");
    }

    /**
     * DT 3.2.24 — IDOR Protection: Confirms that updating another user's profile throws 404 (Hidden).
     */
    @Test
    @DisplayName("Update: Modifying other user's profile throws 404 (IDOR protection)")
    void updateProfile_IdMismatch_Throws404() {
        assertThrows(UserNotFoundException.class, () -> 
            profileService.updateProfile("other-id", new ProfileUpdateRequest("Name", "123"), "my-id"));
    }

    /**
     * RF 2.1.6 — Profile Update: Confirms successful update when IDs match.
     */
    @Test
    @DisplayName("Update: Own profile update succeeds")
    void updateProfile_Success() {
        String userId = "my-id";
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        ProfileUpdateRequest request = new ProfileUpdateRequest("New Name", "999");
        profileService.updateProfile(userId, request, userId);

        verify(user).setName("New Name");
        verify(user).setPhone("999");
        verify(userRepository).findById(userId);
    }

    /**
     * Edge Case: User not found in DB should throw UserNotFoundException.
     */
    @Test
    @DisplayName("Update: Missing user in database throws 404")
    void updateProfile_NotFound_ThrowsException() {
        String userId = "my-id";
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> 
            profileService.updateProfile(userId, new ProfileUpdateRequest("Any", "123"), userId));
    }
}
