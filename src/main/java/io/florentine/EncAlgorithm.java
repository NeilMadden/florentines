package io.florentine;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.Function;

import javax.crypto.spec.IvParameterSpec;

import io.florentine.Florentine.Packet;

public enum EncAlgorithm {
    A256SIV("AES/CTR/NoPadding", tag -> new IvParameterSpec(tag, 0, 16));

    final String cipherAlgorithm;
    final Function<byte[], AlgorithmParameterSpec> parameterSpecFunction;

    EncAlgorithm(String cipherAlgorithm, Function<byte[], AlgorithmParameterSpec> specFunction) {
        this.cipherAlgorithm = cipherAlgorithm;
        this.parameterSpecFunction = specFunction;
    }

    void encrypt(Key key, Packet packet) {
        Crypto.encryptInPlace(cipherAlgorithm, key, packet.content, parameterSpecFunction.apply(packet.siv));
    }

    void decrypt(Key key, Packet packet) {
        Crypto.decryptInPlace(cipherAlgorithm, key, packet.content, parameterSpecFunction.apply(packet.siv));
    }

    String getKeyAlgorithm() {
        return cipherAlgorithm.split("/")[0];
    }

    int getKeySizeBytes() {
        return 32;
    }

    @Override
    public String toString() {
        return name();
    }
}
