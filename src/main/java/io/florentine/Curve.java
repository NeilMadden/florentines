package io.florentine;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.XECKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;

public enum Curve {
    P_256("secp256r1"),
    P_384("secp384r1"),
    P_521("secp521r1"),
    X25519(NamedParameterSpec.X25519),
    X448(NamedParameterSpec.X448);

    private final AlgorithmParameterSpec parameters;

    Curve(String name) {
        try {
            var parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(name));
            this.parameters = parameters.getParameterSpec(ECParameterSpec.class);
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
            throw new IllegalStateException("Cannot lookup parameters for standard curve: " + name, e);
        }
    }

    Curve(AlgorithmParameterSpec parameters) {
        this.parameters = parameters;
    }

    AlgorithmParameterSpec getParameters() {
        return parameters;
    }

    static Curve forKey(Key key) {
        if (key instanceof ECKey) {
            for (Curve candidate : values()) {
                if (candidate.parameters.equals(((ECKey) key).getParams())) {
                    return candidate;
                }
            }
        }
        if (key instanceof XECKey) {
            for (Curve candidate : values()) {
                var keyParams = ((XECKey) key).getParams();
                if (candidate.parameters.equals(keyParams)) {
                    return candidate;
                }
                if (keyParams instanceof NamedParameterSpec && candidate.parameters instanceof NamedParameterSpec) {
                    if (((NamedParameterSpec) keyParams).getName().equals(((NamedParameterSpec) candidate.parameters).getName())) {
                        return candidate;
                    }
                }
            }
        }
        return null;
    }

    String getKeyAlgorithm() {
        return this == X25519 || this == X448 ? "XDH" : "EC";
    }

    PublicKey generatePublic(byte[] x, byte[] y) {
        try {
            var keyFactory = KeyFactory.getInstance(getKeyAlgorithm());
            return keyFactory.generatePublic(getPublicKeySpec(x, y));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException(e);
        }
    }

    KeySpec getPublicKeySpec(byte[] x, byte[] y) {
        if (this == X25519 || this == X448) {
            assert y == null;
            var u = new BigInteger(1, Utils.reverse(x));
            return new XECPublicKeySpec(getParameters(), u);
        } else {
            assert y != null;
            ECPoint w = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
            return new ECPublicKeySpec(w, (ECParameterSpec) getParameters());
        }
    }

    @Override
    public String toString() {
        return name().replace('_', '-');
    }
}
