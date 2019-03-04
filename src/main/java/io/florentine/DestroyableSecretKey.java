package io.florentine;

import static java.util.Objects.checkFromIndexSize;
import static java.util.Objects.requireNonNull;

import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;

final class DestroyableSecretKey implements SecretKey, Destroyable {

    private final String algorithm;
    private final byte[] keyMaterial;
    private final int offset;
    private final int length;
    private volatile boolean destroyed;

    DestroyableSecretKey(byte[] keyMaterial, int offset, int length, String algorithm) {
        this.algorithm = requireNonNull(algorithm, "algorithm");
        this.keyMaterial = requireNonNull(keyMaterial, "keyMaterial");
        this.offset = offset;
        this.length = length;
        checkFromIndexSize(offset, length, keyMaterial.length);
    }

    DestroyableSecretKey(byte[] keyMaterial, String algorithm) {
        this(keyMaterial, 0, keyMaterial.length, algorithm);
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return Arrays.copyOfRange(keyMaterial, offset, offset + length);
    }

    @Override
    public void destroy() {
        destroyed = true;
        Arrays.fill(keyMaterial, (byte) 0);
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }
}