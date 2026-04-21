package io.github.brenomega.authkit.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.domain.user.dto.ProfileUpdateRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.repository.UserRepository;

@Service
public class ProfileService {

    private final UserRepository userRepository;

    public ProfileService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Updates profile info, enforcing that callers can only modify strictly their own data.
     *
     * @param targetUserId        the ID provided in the URI
     * @param request             the validated properties to update
     * @param authenticatedUserId the Subject extracted from the Token context
     * @return the updated user entity
     */
    @Transactional
    public User updateProfile(String targetUserId, ProfileUpdateRequest request, String authenticatedUserId) {
        // Enforce strict horizontal ID level authorization boundary to prevent insecure direct object reference (IDOR).
        // A generic 404 is thrown to halt enumeration attempts.
        if (!targetUserId.equals(authenticatedUserId)) {
            throw new UserNotFoundException();
        }

        User user = userRepository.findById(targetUserId)
                .orElseThrow(UserNotFoundException::new);

        // Update conditionally
        if (request.name() != null) {
            user.setName(request.name());
        }
        if (request.phone() != null) {
            user.setPhone(request.phone());
        }

        return user;
    }
}
