package io.github.brenomega.authkit.util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Utility class for dynamic RSA key generation in test environments (DT 3.2.3).
 *
 * <p>Ensures that no static key strings are committed to the source code by
 * providing on-demand 2048-bit KeyPairs at runtime.</p>
 */
public class RsaKeyGenerator {

    /**
     * Generates a new 2048-bit RSA KeyPair.
     *
     * @return the generated {@link KeyPair}
     * @throws RuntimeException if RSA algorithm is not available
     */
    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("RSA algorithm not found", e);
        }
    }

    /**
     * Encodes a Public Key as a PEM string.
     *
     * @param publicKey the key to encode
     * @return the PEM formatted string
     */
    public static String toPublicPem(PublicKey publicKey) {
        String encoded = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + encoded + "\n-----END PUBLIC KEY-----";
    }

    /**
     * Encodes a Private Key as a PEM string.
     *
     * @param privateKey the key to encode
     * @return the PEM formatted string
     */
    public static String toPrivatePem(PrivateKey privateKey) {
        String encoded = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + encoded + "\n-----END PRIVATE KEY-----";
    }
}
