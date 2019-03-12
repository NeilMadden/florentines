package io.florentine;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

/**
 * Encapsulates all crypto-related code for easy auditing.
 */
final class Crypto {

    static byte[] ecdh(Key secretKey, PublicKey publicKey) throws GeneralSecurityException {
        var keyAgreement = KeyAgreement.getInstance(secretKey.getAlgorithm());
        keyAgreement.init(secretKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }

    static KeyPair generateKeyPair(Curve curve) {
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance(curve.getKeyAlgorithm());
            keyPairGenerator.initialize(curve.getParameters());
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(e);
        }
    }

    static final class HKDF {
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
         * @return the MAC key and the encryption key.
         */
        static SecretKeyPair expand(Key masterKey, MacAlgorithm macAlgorithm, EncAlgorithm encAlgorithm,
                byte[] extraInfo) {
            try {
                var mac = Mac.getInstance(macAlgorithm.getMacAlgorithm());
                mac.init(masterKey);

                assert mac.getMacLength() >= macAlgorithm.getKeySizeBytes() + encAlgorithm.getKeySizeBytes();

                mac.update(extraInfo);
                mac.update((byte) 0);

                var keyMaterial = mac.doFinal();
                return new SecretKeyPair(keyMaterial, macAlgorithm, encAlgorithm);

            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("JVM does not support requested MAC algorithm: " + macAlgorithm, e);
            } catch (InvalidKeyException e) {
                throw new IllegalArgumentException("Invalid master key", e);
            }
        }
    }

    static class SecretKeyPair {
        private final DestroyableSecretKey macKey;
        private final DestroyableSecretKey encKey;

        SecretKeyPair(byte[] keyMaterial, MacAlgorithm macAlgorithm, EncAlgorithm encAlgorithm) {
            var midPoint = keyMaterial.length / 2;

            macKey = new DestroyableSecretKey(keyMaterial, 0, macAlgorithm.getKeySizeBytes(),
                    macAlgorithm.getKeyAlgorithm());
            encKey = new DestroyableSecretKey(keyMaterial, midPoint, encAlgorithm.getKeySizeBytes(),
                    encAlgorithm.getKeyAlgorithm());
        }

        public DestroyableSecretKey getMacKey() {
            return macKey;
        }

        public DestroyableSecretKey getEncKey() {
            return encKey;
        }
    }

    private Crypto() {}
}