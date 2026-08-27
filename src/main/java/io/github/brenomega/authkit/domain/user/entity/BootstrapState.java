package io.github.brenomega.authkit.domain.user.entity;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** Singleton database guard that serializes the one-shot first-admin bootstrap. */
@Entity
@Table(name = "authkit_bootstrap_state")
public class BootstrapState {

    public static final int SINGLETON_ID = 1;

    @Id
    private Integer id;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "admin_user_id")
    private UUID adminUserId;

    protected BootstrapState() {
    }

    public BootstrapState(int id) {
        this.id = id;
    }

    public Integer getId() {
        return id;
    }

    public Instant getCompletedAt() {
        return completedAt;
    }

    public UUID getAdminUserId() {
        return adminUserId;
    }

    public boolean isCompleted() {
        return completedAt != null;
    }

    public void complete(UUID userId, Instant now) {
        if (isCompleted()) {
            throw new IllegalStateException("Platform administrator bootstrap is already complete");
        }
        this.adminUserId = userId;
        this.completedAt = now;
    }
}
