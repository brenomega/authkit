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
 * Persists tenant-owned accounts and exposes explicit locks for identity and lifecycle transitions.
 * Tenant filtering is supplied by the service-layer persistence aspect for tenant
 * JWTs; platform administration and unauthenticated ceremonies must enforce their
 * own scope and identity rules.
 */
@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmail(String email);

    /** Locks a normalized email identity while a recovery request replaces its external token. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where u.email = :email")
    Optional<User> findByEmailForUpdate(@Param("email") String email);

    Optional<User> findByEmailConfirmationToken(String emailConfirmationToken);

    /** Locks the account addressed by a confirmation-token digest for single transition processing. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where u.emailConfirmationToken = :tokenHash")
    Optional<User> findByEmailConfirmationTokenForUpdate(@Param("tokenHash") String tokenHash);

    boolean existsByPendingEmail(String pendingEmail);

    /** Locks the account addressed by an email-change digest during confirmation. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where u.emailChangeTokenHash = :tokenHash")
    Optional<User> findByEmailChangeTokenHashForUpdate(@Param("tokenHash") String tokenHash);

    @Query("select u.id from User u where u.deletedAt is not null and u.deletedAt < :cutoff order by u.deletedAt asc")
    List<UUID> findDeletedIdsBefore(@Param("cutoff") Instant cutoff, Pageable pageable);

    @Query("select u.id from User u where u.accountState = :state and " +
        "u.deletionRequestedAt <= :cutoff order by u.deletionRequestedAt " +
        "asc")
    List<UUID> findDeletionPendingIdsBefore(@Param("state") AccountState state,
                                            @Param("cutoff") Instant cutoff,
                                            Pageable pageable);

    /** Locks an account so scheduled anonymization can recheck eligibility before mutation. */
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
