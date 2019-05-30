package io.florentine;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import io.florentine.Florentine.Secret;

public enum EncAlgorithm {
    A256SIV("AES/CTR/NoPadding", 16);

    private final String algorithm;
    private final int ivLen;

    EncAlgorithm(String algorithm, int ivLen) {
        this.algorithm = algorithm;
        this.ivLen = ivLen;
    }

    byte[] encrypt(Key key, Secret packet, byte[] tag) {
        byte[] siv = getSiv(tag);
        process(key, packet, siv);
        return siv;
    }

    byte[] getSiv(byte[] tag) {
        byte[] siv = Arrays.copyOfRange(tag, 32, 32 + ivLen);
        siv[8]  &= 0x7F;
        siv[12] &= 0x7F;
        return siv;
    }

    void decrypt(Key key, Secret packet) {
        process(key, packet, packet.siv);
    }

    void process(Key key, Secret packet, byte[] siv) {
        try {
            var cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(siv));
            cipher.doFinal(packet.bytes, 0, packet.bytes.length, packet.bytes);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
}
