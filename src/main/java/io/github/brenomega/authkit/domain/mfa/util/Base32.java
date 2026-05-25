package io.github.brenomega.authkit.domain.mfa.util;

import java.io.ByteArrayOutputStream;
import java.util.Locale;

/**
 * Minimal RFC 4648 Base32 codec without padding.
 */
public final class Base32 {

    private static final char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

    private Base32() {
    }

    public static String encode(byte[] data) {
        StringBuilder result = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0;
        int bitsLeft = 0;

        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xff);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                result.append(ALPHABET[(buffer >> (bitsLeft - 5)) & 0x1f]);
                bitsLeft -= 5;
            }
        }

        if (bitsLeft > 0) {
            result.append(ALPHABET[(buffer << (5 - bitsLeft)) & 0x1f]);
        }

        return result.toString();
    }

    public static byte[] decode(String value) {
        String normalized = value.replace("=", "")
                .replace(" ", "")
                .toUpperCase(Locale.ROOT);
        int buffer = 0;
        int bitsLeft = 0;
        ByteArrayOutputStream output = new ByteArrayOutputStream(normalized.length() * 5 / 8);

        for (int i = 0; i < normalized.length(); i++) {
            int index = alphabetIndex(normalized.charAt(i));
            if (index < 0) {
                throw new IllegalArgumentException("Invalid Base32 character");
            }
            buffer = (buffer << 5) | index;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                output.write((buffer >> (bitsLeft - 8)) & 0xff);
                bitsLeft -= 8;
            }
        }

        return output.toByteArray();
    }

    private static int alphabetIndex(char c) {
        if (c >= 'A' && c <= 'Z') {
            return c - 'A';
        }
        if (c >= '2' && c <= '7') {
            return c - '2' + 26;
        }
        return -1;
    }
}
