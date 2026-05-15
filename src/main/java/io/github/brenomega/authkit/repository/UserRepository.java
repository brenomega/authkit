package io.github.brenomega.authkit.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import io.github.brenomega.authkit.domain.user.entity.User;

/**
 * Spring Data JPA repository for the {@link User} entity (DT 3.1.4).
 *
 * <p>Acts as an output adapter for the persistence layer, deliberately kept
 * separate from the domain package to isolate data-access technology from
 * the business model.</p>
 */
@Repository
public interface UserRepository extends JpaRepository<User, java.util.UUID> {

    /**
     * Finds a user by their email address.
     *
     * @param email the email to search for
     * @return an {@link Optional} containing the user, or empty if not found
     */
    Optional<User> findByEmail(String email);
}
