package io.github.brenomega.authkit.infrastructure.security;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import io.github.brenomega.authkit.domain.user.entity.User;

/**
 * Adapter that bridges the domain {@link User} entity with Spring Security's
 * {@link UserDetails} contract (DT 3.2.10).
 *
 * <p>This wrapper exists so the JPA entity remains completely agnostic of the
 * security framework. The {@code ROLE_} prefix required by Spring Security
 * is applied here when converting the domain {@code Role} enum to a
 * {@link GrantedAuthority} (DT 3.2.9).</p>
 *
 * @see User
 */
public class SecurityUser implements UserDetails {

    private final User user;

    /**
     * Wraps the given domain entity.
     *
     * @param user the domain user entity (must not be {@code null})
     */
    public SecurityUser(User user) {
        this.user = user;
    }

    /**
     * Returns the authorities granted to the user.
     *
     * <p>The domain {@code Role} name is prefixed with {@code ROLE_} to
     * comply with Spring Security's default role-checking conventions
     * (DT 3.2.9).</p>
     *
     * @return a singleton list containing the user's granted authority
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()));
    }

    /** @return the hashed password stored in the domain entity */
    @Override
    public String getPassword() {
        return user.getPassword();
    }

    /** @return the user's email, used as the principal identifier for login */
    @Override
    public String getUsername() {
        return user.getEmail();
    }

    /**
     * Indicates whether the user's account has not expired.
     *
     * <p><strong>Placeholder:</strong> always returns {@code true} until
     * account expiration logic is implemented as part of the session
     * management RFs (RF 2.1.10).</p>
     *
     * @return {@code true} (default — no expiration policy yet)
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * Indicates whether the user's account is not locked.
     *
     * <p><strong>Placeholder:</strong> always returns {@code true} until
     * the progressive lockout policy is implemented (DT 3.2.23,
     * RF 2.1.11).</p>
     *
     * @return {@code true} (default — no lockout policy yet)
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * Indicates whether the user's credentials (password) have not expired.
     *
     * <p><strong>Placeholder:</strong> always returns {@code true} until
     * credential rotation policies are defined.</p>
     *
     * @return {@code true} (default — no credential expiration yet)
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * Indicates whether the user account is enabled.
     *
     * <p><strong>Placeholder:</strong> always returns {@code true} until
     * email confirmation (RF 2.1.7) and account deletion (RF 2.1.9)
     * workflows are implemented.</p>
     *
     * @return {@code true} (default — no enable/disable logic yet)
     */
    @Override
    public boolean isEnabled() {
        return true;
    }

    /**
     * Provides direct access to the underlying domain entity.
     *
     * @return the wrapped {@link User}
     */
    public User getUser() {
        return user;
    }
}
