package io.florentine;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.Function;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public enum EncAlgorithm {
    A256SIV("AES/CTR/NoPadding", tag -> new IvParameterSpec(tag, 0, 16));

    final String cipherAlgorithm;
    final Function<byte[], AlgorithmParameterSpec> parameterSpecFunction;

    EncAlgorithm(String cipherAlgorithm, Function<byte[], AlgorithmParameterSpec> specFunction) {
        this.cipherAlgorithm = cipherAlgorithm;
        this.parameterSpecFunction = specFunction;
    }

    Cipher getCipher(int mode, Key key, byte[] siv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException {
        var cipher = Cipher.getInstance(cipherAlgorithm);
        cipher.init(mode, key, parameterSpecFunction.apply(siv));
        return cipher;
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
