package io.florentine;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.json.JSONObject;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class FlorentineTest {

    private SecretKey hkdfKey;

    @BeforeClass
    public void generateKeys() throws Exception {
        var keyGenerator = KeyGenerator.getInstance("HMACSHA512");
        keyGenerator.init(512);
        hkdfKey = keyGenerator.generateKey();
    }

    @Test
    public void testBasic() throws Exception {
        var florentine = Florentine.builder()
                .audience("a", "b")
                .keyId("test")
                .addPublic(new JSONObject().put("a", "b"))
                .addSecret(new JSONObject().put("b", true))
                .buildSecret(hkdfKey);

        var out = florentine.toString();

        System.out.println(out);
    }
}