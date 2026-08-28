package io.github.brenomega.authkit.repository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.enums.Role;

/**
 * Provides account lookup and explicit tenant-scoped administration queries.
 */
@Repository
public interface UserRepository extends JpaRepository<User, java.util.UUID> {

    Optional<User> findByEmail(String email);

    Optional<User> findByEmailConfirmationToken(String emailConfirmationToken);

    @Query("select u.id from User u where u.deletedAt is not null and u.deletedAt < :cutoff order by u.deletedAt asc")
    List<UUID> findDeletedIdsBefore(@Param("cutoff") Instant cutoff, Pageable pageable);

    /** Returns only non-deleted users belonging to the explicit tenant. */
    List<User> findByTenantIdAndDeletedAtIsNull(UUID tenantId, Pageable pageable);

    @Modifying
    @Query("delete from User u where u.id in :ids")
    long purgeDeletedByIdIn(@Param("ids") Collection<UUID> ids);

    long countByRoleAndDeletedAtIsNull(Role role);
}
