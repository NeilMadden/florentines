package io.florentine;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class Crypto {
    static final SecureRandom SECURE_RANDOM = chooseSecureRandom();
    static final String MAC_ALGORITHM = "HmacSHA256";
    static final String ENC_ALGORITHM = "AES/CTR/NoPadding";

    static byte[] randomBytes(int size) {
        return SECURE_RANDOM.generateSeed(size);
    }

    static byte[] hmac(byte[] key, byte tag, byte[] data) {
        return hmac(new SecretKeySpec(key, 0, 16, MAC_ALGORITHM), tag, data);
    }

    static byte[] hmac(Key key, byte tag, byte[] data) {
        try {
            Mac hmac = Mac.getInstance(MAC_ALGORITHM);
            hmac.init(key);
            hmac.update(tag);
            return hmac.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    static byte[] encrypt(byte[] key, byte[] tag, byte[] data) {
        // The SIV is the last 16 bytes of the tag.
        // Clear the 31st and 63rd bits (counting from the right) as per
        // https://tools.ietf.org/html/rfc5297#section-2.6
        tag[16 + 8] &= 0x7F;
        tag[16 + 12] &= 0x7F;

        try {
            var cipher = Cipher.getInstance(ENC_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(tag, 16, 16));
            cipher.doFinal(data, 0, data.length, data);
            return cipher.getIV();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] decrypt(byte[] key, byte[] siv, byte[] data) {
        try {
            var cipher = Cipher.getInstance(ENC_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(siv));
            return cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Decryption failed");
        }
    }

    private static SecureRandom chooseSecureRandom() {
        final String[] PREFERRED_PRNGS = {
                "NativePRNGNonBlocking", "NativePRNG", "DRBG"
        };
        for (String alg : PREFERRED_PRNGS) {
            try {
                return SecureRandom.getInstance(alg);
            } catch (NoSuchAlgorithmException e) {
                // Skip this one
            }
        }

        if (System.getProperty("os.name").toLowerCase(Locale.ROOT).startsWith("windows")) {
            // On Windows use the SHA1PRNG. While this is a weak algorithm, the default seed source on Windows is
            // native code that calls CryptGenRandom(). By using SecureRandom.generateSeed() we will bypass the
            // weak SHA1PRNG and go straight to this high-quality seed generator.
            try {
                return SecureRandom.getInstance("SHA1PRNG");
            } catch (NoSuchAlgorithmException e) {
                // Skip this one
            }
        }

        throw new IllegalStateException("Unable to find a high-quality SecureRandom source");
    }

    private Crypto() {}
}
