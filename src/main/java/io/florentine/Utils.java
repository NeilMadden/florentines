package io.florentine;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Iterator;

import javax.crypto.KeyAgreement;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

final class Utils {

    static <T> Iterable<T> concat(Iterable<T> a, Iterable<T> b, Iterable<T> c) {
        Iterator<T> it1 = a.iterator();
        Iterator<T> it2 = b.iterator();
        Iterator<T> it3 = c.iterator();

        return () -> new Iterator<>() {
            @Override
            public boolean hasNext() {
                return it1.hasNext() || it2.hasNext() || it3.hasNext();
            }

            @Override
            public T next() {
                return it1.hasNext() ? it1.next() : it2.hasNext() ? it2.next() : it3.next();
            }
        };
    }

    static byte[] ecdh(String keyAgreementAlgorithm, Key secretKey, PublicKey publicKey)
            throws GeneralSecurityException {
        var keyAgreement = KeyAgreement.getInstance(keyAgreementAlgorithm);
        keyAgreement.init(secretKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }

    static void destroyKeyMaterial(Destroyable... keys) {
        for (Destroyable key : keys) {
            if (key != null) {
                try {
                    key.destroy();
                } catch (DestroyFailedException e) {
                    // Ignore
                }
            }
        }
    }

    static byte[] sha512(byte[]...inputs) {
        try {
            var hash = MessageDigest.getInstance("SHA-512");

            for (byte[] input : inputs) {
                hash.update(input);
            }

            return hash.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-512 not available", e);
        }
    }
}
