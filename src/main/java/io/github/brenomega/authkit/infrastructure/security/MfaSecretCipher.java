package io.github.brenomega.authkit.infrastructure.security;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

/**
 * Encrypts TOTP shared secrets before database persistence.
 */
@Component
public class MfaSecretCipher {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String KDF = "PBKDF2WithHmacSHA256";
    private static final String ENVELOPE_VERSION = "v3";
    private static final String PBKDF2_ENVELOPE_VERSION = "v2";
    private static final int AES_KEY_BITS = 256;
    private static final int SALT_BYTES = 16;
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final SecureRandom secureRandom = new SecureRandom();
    private final String currentKeyId;
    private final String currentSecret;
    private final Map<String, String> previousSecrets;
    private final int kdfIterations;

    public MfaSecretCipher(AuthProperties authProperties) {
        this.currentKeyId = authProperties.getMfa().getSecretEncryptionKeyId();
        this.currentSecret = authProperties.getMfa().getSecretEncryptionKey();
        this.previousSecrets = parsePreviousSecrets(authProperties.getMfa().getPreviousSecretEncryptionKeys());
        this.kdfIterations = authProperties.getMfa().getSecretEncryptionKdfIterations();
    }

    public String encrypt(String plaintext) {
        try {
            byte[] salt = new byte[SALT_BYTES];
            byte[] iv = new byte[IV_BYTES];
            secureRandom.nextBytes(salt);
            secureRandom.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, deriveKey(currentSecret, salt), new GCMParameterSpec(TAG_BITS, iv));
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            String payload = Base64.getEncoder().encodeToString(ByteBuffer.allocate(iv.length + encrypted.length)
                    .put(iv)
                    .put(encrypted)
                    .array());
            return ENVELOPE_VERSION + ":"
                    + currentKeyId
                    + ":"
                    + kdfIterations
                    + ":"
                    + Base64.getEncoder().encodeToString(salt)
                    + ":"
                    + payload;
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Unable to encrypt MFA secret", ex);
        }
    }

    public String decrypt(String encryptedValue) {
        if (encryptedValue != null && encryptedValue.startsWith(ENVELOPE_VERSION + ":")) {
            return decryptVersioned(encryptedValue);
        }
        if (encryptedValue != null && encryptedValue.startsWith(PBKDF2_ENVELOPE_VERSION + ":")) {
            return decryptPbkdf2WithoutKeyId(encryptedValue);
        }
        return decryptLegacyWithoutKeyId(encryptedValue);
    }

    private String decryptVersioned(String encryptedValue) {
        String[] parts = encryptedValue.split(":", 5);
        if ((parts.length != 4 && parts.length != 5) || !ENVELOPE_VERSION.equals(parts[0])) {
            throw new IllegalStateException("Unable to decrypt MFA secret");
        }
        String keyId = parts[1];
        int iterations = kdfIterations;
        int saltIndex = 2;
        int payloadIndex = 3;
        if (parts.length == 5) {
            try {
                iterations = Integer.parseInt(parts[2]);
            } catch (NumberFormatException ex) {
                throw new IllegalStateException("Unable to decrypt MFA secret", ex);
            }
            saltIndex = 3;
            payloadIndex = 4;
        }
        String keyMaterial = keyMaterialFor(keyId);
        try {
            byte[] salt = Base64.getDecoder().decode(parts[saltIndex]);
            byte[] combined = Base64.getDecoder().decode(parts[payloadIndex]);
            if (combined.length <= IV_BYTES) {
                throw new IllegalArgumentException("Invalid encrypted MFA secret");
            }
            byte[] iv = java.util.Arrays.copyOfRange(combined, 0, IV_BYTES);
            byte[] encrypted = java.util.Arrays.copyOfRange(combined, IV_BYTES, combined.length);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, deriveKey(keyMaterial, salt, iterations), new GCMParameterSpec(TAG_BITS, iv));
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Unable to decrypt MFA secret", ex);
        }
    }

    private String decryptPbkdf2WithoutKeyId(String encryptedValue) {
        String[] parts = encryptedValue.split(":", 3);
        if (parts.length != 3 || !PBKDF2_ENVELOPE_VERSION.equals(parts[0])) {
            throw new IllegalStateException("Unable to decrypt MFA secret");
        }
        byte[] salt;
        byte[] combined;
        try {
            salt = Base64.getDecoder().decode(parts[1]);
            combined = Base64.getDecoder().decode(parts[2]);
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("Unable to decrypt MFA secret", ex);
        }
        for (String keyMaterial : candidateKeyMaterials()) {
            String plaintext = tryDecryptWithPbkdf2Key(keyMaterial, salt, combined);
            if (plaintext != null) {
                return plaintext;
            }
        }
        throw new IllegalStateException("Unable to decrypt MFA secret");
    }

    private String decryptLegacyWithoutKeyId(String encryptedValue) {
        byte[] combined;
        try {
            combined = Base64.getDecoder().decode(encryptedValue);
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("Unable to decrypt MFA secret", ex);
        }
        for (String keyMaterial : candidateKeyMaterials()) {
            String plaintext = tryDecryptWithLegacyKey(keyMaterial, combined);
            if (plaintext != null) {
                return plaintext;
            }
        }
        throw new IllegalStateException("Unable to decrypt MFA secret");
    }

    private String tryDecryptWithPbkdf2Key(String keyMaterial, byte[] salt, byte[] combined) {
        try {
            if (combined.length <= IV_BYTES) {
                throw new IllegalArgumentException("Invalid encrypted MFA secret");
            }
            byte[] iv = Arrays.copyOfRange(combined, 0, IV_BYTES);
            byte[] encrypted = Arrays.copyOfRange(combined, IV_BYTES, combined.length);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, deriveKey(keyMaterial, salt), new GCMParameterSpec(TAG_BITS, iv));
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            return null;
        }
    }

    private String tryDecryptWithLegacyKey(String keyMaterial, byte[] combined) {
        try {
            if (combined.length <= IV_BYTES) {
                throw new IllegalArgumentException("Invalid encrypted MFA secret");
            }
            byte[] iv = Arrays.copyOfRange(combined, 0, IV_BYTES);
            byte[] encrypted = Arrays.copyOfRange(combined, IV_BYTES, combined.length);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, legacyKey(keyMaterial), new GCMParameterSpec(TAG_BITS, iv));
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            return null;
        }
    }

    private SecretKeySpec deriveKey(String keyMaterial, byte[] salt) {
        return deriveKey(keyMaterial, salt, kdfIterations);
    }

    private SecretKeySpec deriveKey(String keyMaterial, byte[] salt, int iterations) {
        char[] secret = keyMaterial.toCharArray();
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF);
            KeySpec spec = new PBEKeySpec(secret, salt, iterations, AES_KEY_BITS);
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Unable to derive MFA encryption key", ex);
        } finally {
            Arrays.fill(secret, '\0');
        }
    }

    private SecretKeySpec legacyKey(String keyMaterial) {
        try {
            byte[] key = MessageDigest.getInstance("SHA-256")
                    .digest(keyMaterial.getBytes(StandardCharsets.UTF_8));
            return new SecretKeySpec(key, "AES");
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Unable to derive MFA encryption key", ex);
        }
    }

    private String keyMaterialFor(String keyId) {
        if (currentKeyId.equals(keyId)) {
            return currentSecret;
        }
        String previous = previousSecrets.get(keyId);
        if (previous != null) {
            return previous;
        }
        throw new IllegalStateException("Unable to decrypt MFA secret");
    }

    private java.util.List<String> candidateKeyMaterials() {
        java.util.ArrayList<String> candidates = new java.util.ArrayList<>();
        candidates.add(currentSecret);
        candidates.addAll(previousSecrets.values());
        return candidates;
    }

    private Map<String, String> parsePreviousSecrets(String configuredPreviousSecrets) {
        Map<String, String> parsed = new LinkedHashMap<>();
        if (configuredPreviousSecrets == null || configuredPreviousSecrets.isBlank()) {
            return Map.of();
        }
        String[] entries = configuredPreviousSecrets.split(";");
        for (String entry : entries) {
            if (entry.isBlank()) {
                continue;
            }
            int separator = entry.indexOf('=');
            if (separator <= 0 || separator == entry.length() - 1) {
                throw new IllegalStateException("Invalid MFA previous encryption key configuration");
            }
            String keyId = entry.substring(0, separator).trim();
            String keyMaterial = entry.substring(separator + 1).trim();
            if (keyId.isBlank() || keyMaterial.isBlank() || currentKeyId.equals(keyId)) {
                throw new IllegalStateException("Invalid MFA previous encryption key configuration");
            }
            parsed.put(keyId, keyMaterial);
        }
        return Map.copyOf(parsed);
    }
}
