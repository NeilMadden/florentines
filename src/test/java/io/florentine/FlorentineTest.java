package io.florentine;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.json.JSONObject;
import org.testng.annotations.Test;

public class FlorentineTest {

    @Test
    public void testIt() throws Exception {
        Key key = Florentine.generateKey();
        Florentine florentine = Florentine.create(key, new JSONObject().put("kid", "test"))
                .addPublic("This is a public bit of data")
                .addSecret("This is a secret bit of data")
                .addCaveat(new JSONObject().put("exp", Instant.now().plus(5, ChronoUnit.MINUTES).getEpochSecond()));

        String str = florentine.serialize();

        Florentine copy = Florentine.parse(str);
        boolean valid = copy.verifySignature(key);

        assertThat(valid).isTrue();
    }

}