package io.florentine;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPairGenerator;
import java.security.spec.NamedParameterSpec;

import javax.crypto.KeyGenerator;

import org.json.JSONObject;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class FlorentineTest {

    private FlorentineKey sender;
    private FlorentineKey reciever;
    @BeforeClass
    public void generateKeys() throws Exception {
        var keyGenerator = KeyGenerator.getInstance("HMACSHA512");
        keyGenerator.init(512);
        var senderKey = keyGenerator.generateKey();

        sender = FlorentineKey.builder()
                .kdf(KdfAlgorithm.HKDF)
                .mac(MacAlgorithm.HS512)
                .enc(EncAlgorithm.A256SIV)
                .keyId("test")
                .secretKey(senderKey)
                .build();

        var receiverKey = keyGenerator.generateKey();
        reciever = FlorentineKey.builder()
                .kdf(KdfAlgorithm.HKDF)
                .mac(MacAlgorithm.HS512)
                .enc(EncAlgorithm.A256SIV)
                .keyId("test")
                .secretKey(senderKey)
                .build();
    }

    @Test
    public void testBasic() throws Exception {
        var florentine = Florentine.builder()
                .from(sender)
                .addPublic(new JSONObject().put("a", "b"))
                .addSecret(new JSONObject().put("b", true))
                .build();

        var out = florentine.toString();
        System.out.println(out);

        var parsed = Florentine.decode(out);
        assertThat(parsed.verifySignature(sender, sender)).isTrue();
    }

    @Test
    public void testPublicKey() throws Exception {
        var keyPairGenerator = KeyPairGenerator.getInstance("XDH");
        keyPairGenerator.initialize(NamedParameterSpec.X25519);
        var senderKeys = keyPairGenerator.generateKeyPair();
        var receiverKeys = keyPairGenerator.generateKeyPair();

        var sender = FlorentineKey.builder()
                .kdf(KdfAlgorithm.ECDH)
                .mac(MacAlgorithm.HS512)
                .enc(EncAlgorithm.A256SIV)
                .keyId("test")
                .secretKey(senderKeys.getPrivate())
                .publicKey(senderKeys.getPublic())
                .build();

        var receiver = FlorentineKey.builder()
                .kdf(KdfAlgorithm.ECDH)
                .mac(MacAlgorithm.HS512)
                .enc(EncAlgorithm.A256SIV)
                .keyId("test")
                .secretKey(receiverKeys.getPrivate())
                .publicKey(receiverKeys.getPublic())
                .build();

        var florentine = Florentine.builder()
                .from(sender)
                .to(receiver)
                .addPublic(new JSONObject().put("a", "b"))
                .addSecret(new JSONObject().put("b", true))
                .build();

        florentine.addCaveat(new JSONObject().put("exp", 12345));

        var out = florentine.toString();
        System.out.println(out);

        sender = FlorentineKey.builder()
                .kdf(KdfAlgorithm.ECDH)
                .mac(MacAlgorithm.HS512)
                .enc(EncAlgorithm.A256SIV)
                .keyId("test")
                .publicKey(senderKeys.getPublic())
                .build();

        var parsed = Florentine.decode(out).withMacAlgorithm(MacAlgorithm.HS512);

        parsed.addCaveat(new JSONObject().put("foo", "bar"));

        assertThat(parsed.verifySignature(receiver, sender)).isTrue();
    }
}