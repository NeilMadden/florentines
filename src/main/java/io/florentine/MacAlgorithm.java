package io.florentine;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;

public enum MacAlgorithm {
    HS512("HmacSHA512");

    private final String macAlgorithm;

    MacAlgorithm(String macAlgorithm) {
        this.macAlgorithm = macAlgorithm;
    }

    Mac getMac() {
        try {
            return Mac.getInstance(macAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JVM does not support this MAC algorithm: " + macAlgorithm, e);
        }
    }

    String getMacAlgorithm() {
        return macAlgorithm;
    }

    String getKeyAlgorithm() { return macAlgorithm; }

    int getKeySizeBytes() {
        return 32;
    }

    @Override
    public String toString() {
        return name();
    }
}
