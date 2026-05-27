package io.github.brenomega.authkit.infrastructure.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class MfaSecretCipherTest {

    @Test
    @DisplayName("MFA secrets are encrypted with versioned key identifiers")
    void encrypt_usesVersionedKeyIdentifier() {
        AuthProperties properties = properties(
                "mfa-key-current",
                "current-mfa-secret-material-at-least-32-bytes",
                "");
        MfaSecretCipher cipher = new MfaSecretCipher(properties);

        String encrypted = cipher.encrypt("JBSWY3DPEHPK3PXP");

        assertTrue(encrypted.startsWith("v3:mfa-key-current:"));
        assertEquals("JBSWY3DPEHPK3PXP", cipher.decrypt(encrypted));
    }

    @Test
    @DisplayName("MFA secret key rotation can decrypt ciphertext encrypted with a previous key")
    void decrypt_supportsPreviousKeyMaterial() {
        AuthProperties oldProperties = properties(
                "mfa-key-previous",
                "previous-mfa-secret-material-at-least-32-bytes",
                "");
        String encryptedWithOldKey = new MfaSecretCipher(oldProperties).encrypt("JBSWY3DPEHPK3PXP");

        AuthProperties rotatedProperties = properties(
                "mfa-key-current",
                "current-mfa-secret-material-at-least-32-bytes",
                "mfa-key-previous=previous-mfa-secret-material-at-least-32-bytes");

        assertEquals("JBSWY3DPEHPK3PXP", new MfaSecretCipher(rotatedProperties).decrypt(encryptedWithOldKey));
    }

    private AuthProperties properties(String keyId, String keyMaterial, String previousKeys) {
        AuthProperties properties = new AuthProperties();
        properties.getMfa().setSecretEncryptionKeyId(keyId);
        properties.getMfa().setSecretEncryptionKey(keyMaterial);
        properties.getMfa().setPreviousSecretEncryptionKeys(previousKeys);
        properties.getMfa().setSecretEncryptionKdfIterations(1000);
        return properties;
    }
}
