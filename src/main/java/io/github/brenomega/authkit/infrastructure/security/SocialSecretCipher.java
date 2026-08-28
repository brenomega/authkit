package io.github.brenomega.authkit.infrastructure.security;

import org.springframework.stereotype.Component;

/**
 * Applies the versioned application-secret envelope to social-provider client secrets.
 * It deliberately shares the established key-rotation mechanism with
 * {@link MfaSecretCipher}; callers must never persist or log decrypted values.
 */
@Component
public class SocialSecretCipher {
    private final MfaSecretCipher delegate;
    public SocialSecretCipher(MfaSecretCipher delegate) { this.delegate = delegate; }
    public String encrypt(String plaintext) { return delegate.encrypt(plaintext); }
    public String decrypt(String ciphertext) { return delegate.decrypt(ciphertext); }
}
