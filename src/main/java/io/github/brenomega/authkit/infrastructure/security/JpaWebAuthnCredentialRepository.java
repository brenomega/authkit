package io.github.brenomega.authkit.infrastructure.security;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.stereotype.Component;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.exception.Base64UrlException;

import io.github.brenomega.authkit.domain.passkey.entity.PasskeyCredential;
import io.github.brenomega.authkit.repository.PasskeyCredentialRepository;
import io.github.brenomega.authkit.repository.UserRepository;

@Component
public class JpaWebAuthnCredentialRepository implements CredentialRepository {

    private final UserRepository userRepository;
    private final PasskeyCredentialRepository passkeyCredentialRepository;

    public JpaWebAuthnCredentialRepository(UserRepository userRepository,
                                           PasskeyCredentialRepository passkeyCredentialRepository) {
        this.userRepository = userRepository;
        this.passkeyCredentialRepository = passkeyCredentialRepository;
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        UUID userId = UUID.fromString(username);
        return passkeyCredentialRepository.findByUserIdAndDisabledAtIsNullOrderByCreatedAtDesc(userId)
                .stream()
                .map(this::descriptor)
                .collect(Collectors.toUnmodifiableSet());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        UUID userId = UUID.fromString(username);
        return userRepository.findById(userId)
                .filter(user -> !user.isDeleted())
                .map(user -> userHandle(user.getId()));
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        try {
            UUID userId = UUID.fromString(new String(userHandle.getBytes(), StandardCharsets.UTF_8));
            return userRepository.findById(userId)
                    .filter(user -> !user.isDeleted())
                    .map(user -> user.getId().toString());
        } catch (IllegalArgumentException ex) {
            return Optional.empty();
        }
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        Optional<String> username = getUsernameForUserHandle(userHandle);
        if (username.isEmpty()) {
            return Optional.empty();
        }
        UUID userId = UUID.fromString(username.get());
        return passkeyCredentialRepository.findByCredentialIdAndDisabledAtIsNull(credentialId.getBase64Url())
                .filter(credential -> credential.getUserId().equals(userId))
                .map(this::registeredCredential);
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return passkeyCredentialRepository.findByCredentialId(credentialId.getBase64Url())
                .stream()
                .filter(PasskeyCredential::isActive)
                .map(this::registeredCredential)
                .collect(Collectors.toUnmodifiableSet());
    }

    public static ByteArray userHandle(UUID userId) {
        return new ByteArray(userId.toString().getBytes(StandardCharsets.UTF_8));
    }

    private PublicKeyCredentialDescriptor descriptor(PasskeyCredential credential) {
        return PublicKeyCredentialDescriptor.builder()
                .id(byteArray(credential.getCredentialId()))
                .transports(transports(credential.getTransports()))
                .build();
    }

    private RegisteredCredential registeredCredential(PasskeyCredential credential) {
        return RegisteredCredential.builder()
                .credentialId(byteArray(credential.getCredentialId()))
                .userHandle(userHandle(credential.getUserId()))
                .publicKeyCose(byteArray(credential.getPublicKeyCose()))
                .signatureCount(credential.getSignatureCount())
                .transports(transports(credential.getTransports()))
                .backupEligible(credential.isBackupEligible())
                .backupState(credential.isBackedUp())
                .build();
    }

    private ByteArray byteArray(String base64Url) {
        try {
            return ByteArray.fromBase64Url(base64Url);
        } catch (Base64UrlException ex) {
            throw new IllegalStateException("Persisted WebAuthn credential is not valid base64url", ex);
        }
    }

    private Set<AuthenticatorTransport> transports(String transports) {
        if (transports == null || transports.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(transports.split(","))
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .map(AuthenticatorTransport::of)
                .collect(Collectors.toUnmodifiableSet());
    }
}
