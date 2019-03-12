package io.florentine;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public enum MacAlgorithm {
    HS512("HmacSHA512");

    private final String macAlgorithm;

    MacAlgorithm(String macAlgorithm) {
        this.macAlgorithm = macAlgorithm;
    }

    byte[] authenticate(Key macKey, byte[] data) {
        try {
            var mac = Mac.getInstance(macAlgorithm);
            mac.init(macKey);
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JVM does not support this MAC algorithm: " + macAlgorithm, e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    byte[] authenticate(byte[] key, byte[] data) {
        return authenticate(new SecretKeySpec(key, 0, getKeySizeBytes(), getKeyAlgorithm()), data);
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
