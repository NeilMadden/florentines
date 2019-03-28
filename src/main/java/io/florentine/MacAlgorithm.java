package io.florentine;

import java.security.Key;

public enum MacAlgorithm {
    HS512("HmacSHA512");

    private final String macAlgorithm;

    MacAlgorithm(String macAlgorithm) {
        this.macAlgorithm = macAlgorithm;
    }

    byte[] authenticate(Key macKey, byte[] data) {
        return Crypto.mac(macAlgorithm, macKey, data);
    }

    byte[] authenticate(byte[] key, byte[] data) {
        return authenticate(new DestroyableSecretKey(key, 0, getKeySizeBytes(), getKeyAlgorithm()), data);
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
