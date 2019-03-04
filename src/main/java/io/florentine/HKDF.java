package io.florentine;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

/**
 * Implementation of the Hash-based Key Derivation Function (HKDF).
 *
 * @see <a href="https://tools.ietf.org/html/rfc5869">RFC 5869</a>.
 */
final class HKDF {

    /**
     * Extracts a master key from the given salt and input key material.
     *
     * @param macAlgorithm the MAC algorithm to use.
     * @param salt the random salt argument, may be null.
     * @param inputKeyMaterial the input key material.
     * @return the derived master key.
     */
    static SecretKey extract(MacAlgorithm macAlgorithm, byte[] salt, byte[]... inputKeyMaterial) {
        try {
            var mac = Mac.getInstance(macAlgorithm.getMacAlgorithm());
            if (salt == null) {
                salt = new byte[mac.getMacLength()];
            }
            var key = new DestroyableSecretKey(salt, macAlgorithm.getKeyAlgorithm());
            mac.init(key);
            key.destroy();

            for (byte[] ikm : inputKeyMaterial) {
                mac.update(ikm);
            }

            return new DestroyableSecretKey(mac.doFinal(), macAlgorithm.getKeyAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JVM does not support requested MAC algorithm: " + macAlgorithm, e);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Expands a master key into a pair of independent MAC and encryption keys.
     *
     * @param masterKey the HKDF master key, such as one derived by a call to
     * {@link #extract(MacAlgorithm, byte[], byte[]...)}.
     * @param macAlgorithm the MAC algorithm.
     * @param encAlgorithm the encryption algorithm.
     * @param extraInfo any additional information to use in the key derivation. Typically this should include
     *                  algorithm and public key information to ensure the derived keys are cryptographically bound
     *                  to the context.
     * @return an array of two keys - the first element is the MAC key, the second is the encryption key.
     */
    static SecretKey[] expand(Key masterKey, MacAlgorithm macAlgorithm, EncAlgorithm encAlgorithm, byte[] extraInfo) {
        try {
            var mac = Mac.getInstance(macAlgorithm.getMacAlgorithm());
            mac.init(masterKey);

            assert mac.getMacLength() >= macAlgorithm.getKeySizeBytes() + encAlgorithm.getKeySizeBytes();

            mac.update(extraInfo);
            mac.update((byte) 0);

            var keyMaterial = mac.doFinal();
            var midPoint = keyMaterial.length / 2;
            var keys = new SecretKey[2];
            keys[0] = new DestroyableSecretKey(keyMaterial, 0, macAlgorithm.getKeySizeBytes(),
                    macAlgorithm.getKeyAlgorithm());
            keys[1] = new DestroyableSecretKey(keyMaterial, midPoint, encAlgorithm.getKeySizeBytes(),
                    encAlgorithm.getKeyAlgorithm());

            return keys;

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JVM does not support requested MAC algorithm: " + macAlgorithm, e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Invalid master key", e);
        }
    }
}
