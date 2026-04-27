package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import io.github.brenomega.authkit.domain.user.dto.ProfileUpdateRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.repository.UserRepository;

/**
 * Unit tests for ProfileService (DT 3.4.5).
 * Validates RF 2.1.6 and IDOR protection (DT 3.2.24).
 */
class ProfileServiceTest {

    private UserRepository userRepository;
    private ProfileService profileService;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        profileService = new ProfileService(userRepository);
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
