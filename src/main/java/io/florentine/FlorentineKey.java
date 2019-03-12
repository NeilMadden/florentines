package io.florentine;

import static java.util.Objects.requireNonNull;

import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.XECPublicKey;
import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;

public class FlorentineKey {

    private final Key secretKey;
    private final PublicKey publicKey;
    private final String keyId;

    private final KdfAlgorithm kdfAlgorithm;
    private final MacAlgorithm macAlgorithm;
    private final EncAlgorithm encAlgorithm;

    private final Curve curve;

    private FlorentineKey(Builder builder) {
        this.secretKey = builder.secretKey;
        this.publicKey = builder.publicKey;
        this.keyId = builder.keyId;
        this.kdfAlgorithm = builder.kdfAlgorithm;
        this.macAlgorithm = builder.macAlgorithm;
        this.encAlgorithm = builder.encAlgorithm;

        Curve secretKeyCurve = Curve.forKey(secretKey);
        Curve publicKeyCurve = Curve.forKey(publicKey);

        if (secretKeyCurve != null && publicKeyCurve != null && secretKeyCurve != publicKeyCurve) {
            throw new IllegalArgumentException("secret key and public key are on different curves");
        }

        this.curve = secretKeyCurve != null ? secretKeyCurve : publicKeyCurve;
    }

    public static Builder builder() {
        return new Builder();
    }

    public boolean isSecret() {
        return secretKey != null;
    }

    public boolean isPublic() {
        return publicKey != null;
    }

    public Key getSecretKey() {
        return secretKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public Curve getCurve() {
        return curve;
    }

    public String getKeyId() {
        return keyId;
    }

    public KdfAlgorithm getKdfAlgorithm() {
        return kdfAlgorithm;
    }

    public MacAlgorithm getMacAlgorithm() {
        return macAlgorithm;
    }

    public EncAlgorithm getEncAlgorithm() {
        return encAlgorithm;
    }

    public JSONObject getPublicClaims() {
        var publicClaims = new JSONObject()
                .put("kdf", kdfAlgorithm.toString())
                .put("mac", macAlgorithm.toString())
                .put("enc", encAlgorithm.toString())
                .putOpt("kid", keyId);

        if (publicKey instanceof ECPublicKey) {
            publicClaims.put("x", ((ECPublicKey) publicKey).getW().getAffineX());
            publicClaims.put("y", ((ECPublicKey) publicKey).getW().getAffineY());
            publicClaims.put("crv", curve.toString());
        }

        if (publicKey instanceof XECPublicKey) {
            publicClaims.put("x", ((XECPublicKey) publicKey).getU());
            publicClaims.put("crv", curve.toString());
        }

        return publicClaims;
    }

    public JSONObject getSecretClaims() {
        if (secretKey != null && secretKey.getEncoded() != null) {
            return new JSONObject().put("k",
                    Base64.getUrlEncoder().withoutPadding().encodeToString(secretKey.getEncoded()));
        }
        return null;
    }

    public static class Builder {
        private Key secretKey;
        private PublicKey publicKey;

        private KdfAlgorithm kdfAlgorithm = KdfAlgorithm.HKDF;
        private MacAlgorithm macAlgorithm = MacAlgorithm.HS512;
        private EncAlgorithm encAlgorithm = EncAlgorithm.A256SIV;

        private String keyId;

        public Builder secretKey(Key key) {
            this.secretKey = key;
            return this;
        }

        public Builder secretKey(byte[] key) {
            return secretKey(new SecretKeySpec(key, macAlgorithm.getKeyAlgorithm()));
        }

        public Builder publicKey(PublicKey publicKey) {
            this.publicKey = publicKey;
            if (!(publicKey instanceof ECPublicKey) && !(publicKey instanceof XECPublicKey)) {
                throw new IllegalArgumentException("unknown public key type");
            }
            return this;
        }

        public Builder kdf(KdfAlgorithm kdfAlgorithm) {
            this.kdfAlgorithm = requireNonNull(kdfAlgorithm);
            return this;
        }

        public Builder mac(MacAlgorithm macAlgorithm) {
            this.macAlgorithm = requireNonNull(macAlgorithm);
            return this;
        }

        public Builder enc(EncAlgorithm encAlgorithm) {
            this.encAlgorithm = requireNonNull(encAlgorithm);
            return this;
        }

        public Builder keyId(String keyId) {
            this.keyId = keyId;
            return this;
        }

        public Builder fromPublicClaims(JSONObject publicClaims) {
            var curve = Curve.valueOf(publicClaims.getString("crv"));

            byte[] x = Base64url.decode(publicClaims.getString("x"));
            byte[] y = null;
            if (publicClaims.has("y")) {
                y = Base64url.decode(publicClaims.getString("y"));
            }

            if (publicClaims.has("kdf")) {
                kdf(KdfAlgorithm.valueOf(publicClaims.getString("kdf").replace('-', '_')));
            }

            if (publicClaims.has("mac")) {
                mac(MacAlgorithm.valueOf(publicClaims.getString("mac")));
            }

            if (publicClaims.has("enc")) {
                enc(EncAlgorithm.valueOf(publicClaims.getString("enc")));
            }

            return publicKey(curve.generatePublic(x, y));
        }

        public Builder fromSecretClaims(JSONObject secretClaims) {
            return secretKey(Base64url.decode(secretClaims.getString("k")));
        }

        public FlorentineKey build() {
            return new FlorentineKey(this);
        }
    }
}
