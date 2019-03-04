package io.florentine;

import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECKey;
import java.security.interfaces.XECKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;

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

    public AlgorithmParameterSpec getParameters() {
        return parameters;
    }

    public <T extends AlgorithmParameterSpec> Optional<T> getParameters(Class<T> specType) {
        if (specType.isInstance(parameters)) {
            return Optional.of(specType.cast(parameters));
        }
        return Optional.empty();
    }

    public static Curve forKey(Key key) {
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

    public String getKeyAgreementAlgorithm() {
        return this == X25519 || this == X448 ? "XDH" : "ECDH";
    }

    @Override
    public String toString() {
        return name().replace('_', '-');
    }
}
