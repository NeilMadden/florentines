package io.florentine;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
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
        try (var buffer = new ByteArrayOutputStream();
             var out = new DataOutputStream(buffer)) {

            packet.write(out);
            out.flush();

            Mac mac = Mac.getInstance(algorithm);
            mac.init(key);
            return mac.doFinal(buffer.toByteArray());
        } catch (GeneralSecurityException e) {
            throw new UnsupportedOperationException("Algorithm " + algorithm + " not supported");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    byte[] authenticate(byte[] key, Packet packet) {
        byte[] keyBytes = Arrays.copyOf(key, 32);
        return authenticate(new SecretKeySpec(keyBytes, algorithm), packet);
    }
}
