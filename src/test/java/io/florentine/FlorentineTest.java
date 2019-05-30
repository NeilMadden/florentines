package io.florentine;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class FlorentineTest {

    private MessageKeys msgKeys;

    @BeforeClass
    public void generateKeys() {
        var keyBytes = new byte[32];
        Florentine.SECURE_RANDOM.nextBytes(keyBytes);
        var macKey = new SecretKeySpec(keyBytes, "HmacSHA512");
        Florentine.SECURE_RANDOM.nextBytes(keyBytes);
        var encKey = new SecretKeySpec(keyBytes, "AES");

        msgKeys = new MessageKeys(macKey, MacAlgorithm.HS512, encKey, EncAlgorithm.A256SIV);
    }

    @Test
    public void testBlah() {

        var florentine = Florentine.builder()
                .keyId("test")
                .addPublic("Hello, World!")
                .addSecret("Super secret message")
                .build(msgKeys)
                .addCaveat(new JSONObject().put("exp", Instant.now().plus(5, ChronoUnit.SECONDS).getEpochSecond()));

        System.out.println("Florentine: " + florentine.serialize());

        var decoded = Florentine.deserialize(MacAlgorithm.HS512, EncAlgorithm.A256SIV, florentine.serialize());
        assertThat(decoded.verify(msgKeys)).isTrue();
    }
}