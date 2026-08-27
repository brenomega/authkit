package io.github.brenomega.authkit.repository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Page;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.Lock;
import jakarta.persistence.LockModeType;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.domain.user.enums.AccountState;

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

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where u.email = :email")
    Optional<User> findByEmailForUpdate(@Param("email") String email);

    /**
     * Finds a user by their email confirmation token.
     *
     * @param emailConfirmationToken the confirmation token to search for
     * @return an {@link Optional} containing the user, or empty if not found
     */
    Optional<User> findByEmailConfirmationToken(String emailConfirmationToken);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where u.emailConfirmationToken = :tokenHash")
    Optional<User> findByEmailConfirmationTokenForUpdate(@Param("tokenHash") String tokenHash);

    boolean existsByPendingEmail(String pendingEmail);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where u.emailChangeTokenHash = :tokenHash")
    Optional<User> findByEmailChangeTokenHashForUpdate(@Param("tokenHash") String tokenHash);

    @Query("select u.id from User u where u.deletedAt is not null and u.deletedAt < :cutoff order by u.deletedAt asc")
    List<UUID> findDeletedIdsBefore(@Param("cutoff") Instant cutoff, Pageable pageable);

    @Query("select u.id from User u where u.accountState = :state and u.deletionRequestedAt <= :cutoff order by u.deletionRequestedAt asc")
    List<UUID> findDeletionPendingIdsBefore(@Param("state") AccountState state,
                                            @Param("cutoff") Instant cutoff,
                                            Pageable pageable);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where u.id = :id")
    Optional<User> findByIdForUpdate(@Param("id") UUID id);

    @Modifying
    @Query("delete from User u where u.id in :ids")
    long purgeDeletedByIdIn(@Param("ids") Collection<UUID> ids);

    long countByRoleAndAccountState(Role role, AccountState accountState);

    long countByRole(Role role);

    @Query("""
            select user from User user
             where :search = ''
                or lower(user.email) like lower(concat('%', :search, '%'))
                or lower(coalesce(user.name, '')) like lower(concat('%', :search, '%'))
            """)
    Page<User> searchForAdministration(@Param("search") String search, Pageable pageable);
}
