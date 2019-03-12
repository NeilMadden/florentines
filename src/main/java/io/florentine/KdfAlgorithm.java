package io.florentine;

import static java.nio.charset.StandardCharsets.US_ASCII;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.SecretKey;

import org.json.JSONObject;

import io.florentine.Crypto.SecretKeyPair;

public enum KdfAlgorithm {
    HKDF {
        @Override
        SecretKeyPair deriveKeys(FlorentineKey senderKey, FlorentineKey recipientKey, JSONObject header) {
            if (recipientKey != null && recipientKey != senderKey) {
                throw new IllegalArgumentException("HKDF does not support recipient keys");
            }

            if (senderKey.getKdfAlgorithm() != HKDF) {
                throw new IllegalArgumentException("Sender key not intended for HKDF");
            }

            var macAlgorithm = senderKey.getMacAlgorithm();
            var encAlgorithm = senderKey.getEncAlgorithm();

            var otherInfo = KdfAlgorithm.otherInfo(this, macAlgorithm, encAlgorithm, header);
            return Crypto.HKDF.expand(senderKey.getSecretKey(), macAlgorithm, encAlgorithm, otherInfo);
        }
    },
    ECDH {
        @Override
        SecretKeyPair deriveKeys(FlorentineKey senderKey, FlorentineKey recipientKey, JSONObject header)
                throws GeneralSecurityException {

            KeyPair ephemeralKeys = null;
            SecretKey masterKey = null;
            byte[] ephemeralStaticSecret = new byte[0];
            byte[] staticStaticSecret = new byte[0];

            var keyPairAlgorithm = recipientKey.getPublicKey().getAlgorithm();

            var macAlgorithm = recipientKey.getMacAlgorithm();
            var encAlgorithm = recipientKey.getEncAlgorithm();

            try {
                if (senderKey.isSecret()) {
                    ephemeralKeys = Crypto.generateKeyPair(recipientKey.getCurve());

                    header.put("epk",
                            Base64.getUrlEncoder().withoutPadding().encodeToString(ephemeralKeys.getPublic().getEncoded()));

                    // Ephemeral-static key agreement
                    ephemeralStaticSecret = Crypto.ecdh(ephemeralKeys.getPrivate(), recipientKey.getPublicKey());

                    // Static-static key agreement
                    staticStaticSecret = Crypto.ecdh(senderKey.getSecretKey(), recipientKey.getPublicKey());
                } else {
                    var keyFactory = KeyFactory.getInstance(keyPairAlgorithm);
                    var encodedBytes = Base64.getUrlDecoder().decode(header.getString("epk"));
                    var epk = keyFactory.generatePublic(new X509EncodedKeySpec(encodedBytes));
                    ephemeralKeys = new KeyPair(epk, null);

                    ephemeralStaticSecret = Crypto.ecdh(recipientKey.getSecretKey(), epk);

                    staticStaticSecret = Crypto.ecdh(recipientKey.getSecretKey(), senderKey.getPublicKey());
                }

                masterKey = Crypto.HKDF.extract(macAlgorithm, null, ephemeralStaticSecret,
                        staticStaticSecret);

                var otherInfo = KdfAlgorithm.otherInfo(this, macAlgorithm, encAlgorithm, header,
                        senderKey.getPublicKey(), ephemeralKeys.getPublic(), recipientKey.getPublicKey());

                return Crypto.HKDF.expand(masterKey, macAlgorithm, encAlgorithm, otherInfo);

            } finally {
                // Clean up any temporary key material
                Arrays.fill(ephemeralStaticSecret, (byte) 0);
                Arrays.fill(staticStaticSecret, (byte) 0);
                if (ephemeralKeys != null) {
                    Utils.destroyKeyMaterial(ephemeralKeys.getPrivate());
                }
                Utils.destroyKeyMaterial(masterKey);
            }
        }
    };

    abstract SecretKeyPair deriveKeys(FlorentineKey sender, FlorentineKey recipient, JSONObject header)
            throws GeneralSecurityException;

    @Override
    public String toString() {
        return name().replace('_', '-');
    }

    private static byte[] otherInfo(KdfAlgorithm kdfAlgorithm, MacAlgorithm macAlgorithm, EncAlgorithm encAlgorithm,
            JSONObject header, PublicKey...publicKeys) {
        try (var baos = new ByteArrayOutputStream();
             var out = new DataOutputStream(baos)) {

            var type = header.has("typ") ? header.getString("typ") : "";
            var algHeader = ascii(kdfAlgorithm.toString(), macAlgorithm.toString(), encAlgorithm.toString(), type);

            out.writeInt(algHeader.length);
            out.write(algHeader);

            out.writeInt(publicKeys.length);

            for (PublicKey publicKey : publicKeys) {
                var encoded = publicKey.getEncoded();
                if (encoded == null) {
                    throw new IllegalArgumentException("encoded public key is null: " + publicKey);
                }
                out.writeInt(encoded.length);
                out.write(encoded);
            }

            out.writeInt((macAlgorithm.getKeySizeBytes() + encAlgorithm.getKeySizeBytes()) * 8);

            out.flush();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Unable to build OtherInfo structure", e);
        }
    }

    private static byte[] ascii(String...strings) {
        var bytes = Arrays.stream(strings).map(s -> s.getBytes(US_ASCII)).toArray(byte[][]::new);
        var size = Arrays.stream(bytes).mapToInt(b -> b.length).sum();
        var buffer = new byte[size];
        var i = 0;
        for (var item : bytes) {
            System.arraycopy(item, 0, buffer, i, item.length);
            i += item.length;
        }
        return buffer;
    }
}
