package io.florentine;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.ECKey;
import java.security.interfaces.XECKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import org.json.JSONObject;

public enum KdfAlgorithm {
    HKDF {
        @Override
        Key[] deriveKeys(Key senderKey, Key recipientKey, JSONObject header, MacAlgorithm macAlgorithm,
                EncAlgorithm encAlgorithm, byte[] additionalInfo) throws GeneralSecurityException {
            if (recipientKey != null) {
                throw new IllegalArgumentException("HKDF does not support recipient keys");
            }
            var hmac = Mac.getInstance(macAlgorithm.getMacAlgorithm());
            assert hmac.getMacLength() >= macAlgorithm.getKeySizeBytes() + encAlgorithm.getKeySizeBytes();
            hmac.init(senderKey);

            String type = header.has("typ") ? header.getString("typ") : "";
            String info = this.toString() + macAlgorithm.toString() + encAlgorithm.toString() + type;
            hmac.update(info.getBytes(StandardCharsets.UTF_8));
            if (additionalInfo != null) {
                hmac.update(additionalInfo);
            }
            hmac.update((byte) 0);
            var keyMaterial = hmac.doFinal();

            var macKey = new SecretKeySpec(keyMaterial, 0, macAlgorithm.getKeySizeBytes(),
                    macAlgorithm.getKeyAlgorthm());
            var encKey = new SecretKeySpec(keyMaterial, 32, encAlgorithm.getKeySizeBytes(),
                    encAlgorithm.getKeyAlgorithm());

            Arrays.fill(keyMaterial, (byte) 0);

            return new Key[] { macKey, encKey };
        }
    },
    ECDH_ESSS {
        @Override
        Key[] deriveKeys(Key senderKey, Key recipientKey, JSONObject header, MacAlgorithm macAlgorithm,
                EncAlgorithm encAlgorithm, byte[] additionalInfo) throws GeneralSecurityException {

            KeyPair ephemeralKeys = null;
            byte[] ephemeralStaticSecret = new byte[0];
            byte[] staticStaticSecret = new byte[0];

            try {
                var keyPairGenerator = KeyPairGenerator.getInstance(senderKey.getAlgorithm());
                keyPairGenerator.initialize(getParameterSpec(senderKey));
                ephemeralKeys = keyPairGenerator.generateKeyPair();

                // Ephemeral-static key agreement
                var keyAgreement = KeyAgreement.getInstance(senderKey.getAlgorithm());
                keyAgreement.init(ephemeralKeys.getPrivate());
                keyAgreement.doPhase(recipientKey, true);
                ephemeralStaticSecret = keyAgreement.generateSecret();

                // Static-static key agreement
                keyAgreement.init(senderKey);
                keyAgreement.doPhase(recipientKey, true);
                staticStaticSecret = keyAgreement.generateSecret();

                var hmac = Mac.getInstance(macAlgorithm.getMacAlgorithm());
                hmac.init(new SecretKeySpec(new byte[hmac.getMacLength()], macAlgorithm.getKeyAlgorthm()));
                hmac.update(ephemeralStaticSecret);
                hmac.update(staticStaticSecret);

                MessageDigest hash = MessageDigest.getInstance("SHA-512");
                hash.update(additionalInfo);
                hash.update(ephemeralKeys.getPublic().getEncoded());
                hash.update(recipientKey.getEncoded());

                var masterKey = new SecretKeySpec(hmac.doFinal(), macAlgorithm.getKeyAlgorthm());
                return HKDF.deriveKeys(masterKey, null, header, macAlgorithm, encAlgorithm, hash.digest());

            } finally {
                // Clean up any temporary key material
                Arrays.fill(ephemeralStaticSecret, (byte) 0);
                Arrays.fill(staticStaticSecret, (byte) 0);
                if (ephemeralKeys != null) {
                    try {
                        ephemeralKeys.getPrivate().destroy();
                    } catch (DestroyFailedException e) {
                        // Ignore
                    }
                }
            }
        }

        private AlgorithmParameterSpec getParameterSpec(Key key) {
            if (key instanceof ECKey) {
                return ((ECKey) key).getParams();
            } else if (key instanceof XECKey) {
                return ((XECKey) key).getParams();
            }
            throw new IllegalArgumentException("unrecognised key: " + key);
        }
    };

    abstract Key[] deriveKeys(Key senderKey, Key recipientKey, JSONObject header, MacAlgorithm macAlgorithm,
            EncAlgorithm encAlgorithm, byte[] additionalInfo) throws GeneralSecurityException;

    @Override
    public String toString() {
        return name().replace('_', '-');
    }
}
