package io.github.brenomega.authkit.infrastructure.security;

import org.springframework.stereotype.Component;

@Component
public class SocialSecretCipher {
    private final MfaSecretCipher delegate;
    public SocialSecretCipher(MfaSecretCipher delegate) { this.delegate = delegate; }
    public String encrypt(String plaintext) { return delegate.encrypt(plaintext); }
    public String decrypt(String ciphertext) { return delegate.decrypt(ciphertext); }
}
