package io.github.brenomega.authkit.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import io.github.brenomega.authkit.domain.user.entity.PasswordHistoryEntry;

@Repository
public interface PasswordHistoryRepository extends JpaRepository<PasswordHistoryEntry, UUID> {

    List<PasswordHistoryEntry> findByUserIdOrderByCreatedAtDesc(UUID userId, Pageable pageable);

    long deleteByUserId(UUID userId);
}
