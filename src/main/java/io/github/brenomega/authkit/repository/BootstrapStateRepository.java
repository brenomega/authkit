package io.github.brenomega.authkit.repository;

import java.util.Optional;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import io.github.brenomega.authkit.domain.user.entity.BootstrapState;

/** Provides exclusive access to the singleton bootstrap-completion guard. */
public interface BootstrapStateRepository extends JpaRepository<BootstrapState, Integer> {

    /** Locks the guard row until the surrounding bootstrap transaction completes. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select state from BootstrapState state where state.id = :id")
    Optional<BootstrapState> findByIdForUpdate(@Param("id") int id);
}
