package io.florentine;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import io.florentine.Florentine.Packet;

public enum MacAlgorithm {
    HS512("HmacSHA512", 32);

    private final String algorithm;
    private final int tagLength;

    MacAlgorithm(String algorithm, int tagLength) {
        this.algorithm = algorithm;
        this.tagLength = tagLength;
    }

    public int getTagLength() {
        return tagLength;
    }

    byte[] authenticate(Key key, Packet packet) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(key);
            mac.update(packet.type);
            mac.update((byte) ((packet.bytes.length >>> 8) & 0xFF));
            mac.update((byte) (packet.bytes.length & 0xFF));
            return mac.doFinal(packet.bytes);
        } catch (GeneralSecurityException e) {
            throw new UnsupportedOperationException("Algorithm " + algorithm + " not supported");
        }
    }

    byte[] authenticate(byte[] key, Packet packet) {
        byte[] keyBytes = Arrays.copyOf(key, 32);
        return authenticate(new SecretKeySpec(keyBytes, algorithm), packet);
    }
}
