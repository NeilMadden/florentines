package io.florentine;

import java.security.Key;

import io.florentine.Florentine.Packet;
import io.florentine.Florentine.Secret;

public class MessageKeys {
    private final Key macKey;
    private final MacAlgorithm macAlgorithm;
    private final Key encKey;
    private final EncAlgorithm encAlgorithm;

    public MessageKeys(Key macKey, MacAlgorithm macAlgorithm, Key encKey, EncAlgorithm encAlgorithm) {
        this.macKey = macKey;
        this.macAlgorithm = macAlgorithm;
        this.encKey = encKey;
        this.encAlgorithm = encAlgorithm;
    }

    public Key getMacKey() {
        return macKey;
    }

    public MacAlgorithm getMacAlgorithm() {
        return macAlgorithm;
    }

    public Key getEncKey() {
        return encKey;
    }

    public EncAlgorithm getEncAlgorithm() {
        return encAlgorithm;
    }

    byte[] authenticate(Packet packet) {
        return macAlgorithm.authenticate(macKey, packet);
    }

    byte[] encrypt(Secret secret, byte[] tag) {
        return encAlgorithm.encrypt(encKey, secret, tag);
    }

    void decrypt(Secret secret) {
        encAlgorithm.decrypt(encKey, secret);
    }

    @Override
    public String toString() {
        return "MessageKeys{" +
                "macKey=" + macKey +
                ", macAlgorithm=" + macAlgorithm +
                ", encKey=" + encKey +
                ", encAlgorithm=" + encAlgorithm +
                '}';
    }
}
