package io.florentine;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;

public final class Florentine {
    private static final Base64.Encoder BASE64URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder BASE64URL_DECODER = Base64.getUrlDecoder();
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final JSONObject header;
    private final List<Packet> contents;
    private final List<Packet> caveats;
    private byte[] tag;

    private final MacAlgorithm macAlgorithm;
    private final EncAlgorithm encAlgorithm;

    Florentine(Builder builder, byte[] tag) {
        this.header = builder.header;
        this.contents = Collections.unmodifiableList(builder.contents);
        this.caveats = new ArrayList<>();
        this.tag = tag;
        this.macAlgorithm = builder.macAlgorithm;
        this.encAlgorithm = builder.encAlgorithm;
    }

    public static Builder builder() {
        return new Builder();
    }

    public Florentine addCaveat(JSONObject caveat) {
        try {
            var mac = Mac.getInstance(macAlgorithm.getMacAlgorithm());
            mac.init(new SecretKeySpec(tag, 0, macAlgorithm.getKeySizeBytes(), macAlgorithm.getKeyAlgorthm()));
            var newTag = mac.doFinal(caveat.toString().getBytes(UTF_8));

            caveats.add(new Packet(PacketType.CAVEAT, caveat.toString()));
            Arrays.fill(this.tag, (byte)0);
            this.tag = newTag;

            return this;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String toString() {
        try (var out = new ByteArrayOutputStream()) {
            for (Packet packet : allPackets()) {
                out.write(packet.packetType.ordinal());
                out.write(encodeLength(packet.content.length));
                out.write(packet.content);
            }

            return BASE64URL_ENCODER.encodeToString(out.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private Iterable<Packet> allPackets() {
        return () -> {
            Iterator<Packet> it1 = Collections.singleton(new Packet(PacketType.HEADER, header.toString())).iterator();
            Iterator<Packet> it2 = contents.iterator();
            Iterator<Packet> it3 = caveats.iterator();

            return new Iterator<>() {
                @Override
                public boolean hasNext() {
                    return it1.hasNext() || it2.hasNext() || it3.hasNext();
                }

                @Override
                public Packet next() {
                    return it1.hasNext() ? it1.next() : it2.hasNext() ? it2.next() : it3.next();
                }
            };
        };
    }

    private static byte[] encodeLength(int length) {
        if (length < 0 || length > 65535) {
            throw new IllegalArgumentException("length cannot be represented in 16 bits");
        }
        return Arrays.copyOf(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(length).array(), 2);
    }

    public static class Builder {
        private final JSONObject header = new JSONObject()
                .put("uid", randomString());
        private final List<Packet> contents = new ArrayList<>();

        private KdfAlgorithm kdfAlgorithm = KdfAlgorithm.HKDF;
        private MacAlgorithm macAlgorithm = MacAlgorithm.HS512;
        private EncAlgorithm encAlgorithm = EncAlgorithm.A256SIV;

        public Builder keyId(String keyId) {
            header.put("kid", keyId);
            return this;
        }

        public Builder type(String type) {
            header.put("typ", type);
            return this;
        }

        public Builder contentType(String contentType) {
            header.put("cty", contentType);
            return this;
        }

        public Builder uniqueId(String uniqueId) {
            header.put("uid", uniqueId);
            return this;
        }

        public Builder audience(String... audience) {
            header.put("aud", Arrays.asList(audience));
            return this;
        }

        public Builder issuer(String issuer) {
            header.put("iss", issuer);
            return this;
        }

        public Builder crit(String... criticalHeaders) {
            header.put("crit", Arrays.asList(criticalHeaders));
            return this;
        }

        public Builder epk(JSONObject ephemeralKey) {
            header.put("epk", ephemeralKey);
            return this;
        }

        public Builder header(String headerName, Object value) {
            header.put(headerName, value);
            return this;
        }

        public Builder headerIfNotNull(String headerName, Object value) {
            header.putOpt(headerName, value);
            return this;
        }

        public Builder addPublic(byte[] content) {
            contents.add(new Packet(PacketType.PUBLIC, content));
            return this;
        }

        public Builder addPublic(String content) {
            return addPublic(content.getBytes(UTF_8));
        }

        public Builder addPublic(JSONObject content) {
            return addPublic(content.toString());
        }

        public Builder addSecret(byte[] content) {
            contents.add(new Packet(PacketType.SECRET, content));
            return this;
        }

        public Builder addSecret(String content) {
            return addSecret(content.getBytes(UTF_8));
        }

        public Builder addSecret(JSONObject content) {
            return addSecret(content.toString());
        }

        public Florentine buildPublic(KeyPair senderKeys, PublicKey recipientKey) {
            try {
                Key[] keys = kdfAlgorithm.deriveKeys(senderKeys.getPrivate(), recipientKey, header, macAlgorithm,
                        encAlgorithm, senderKeys.getPublic().getEncoded());
                return build(keys[0], keys[1]);
            } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
            }
        }

        public Florentine buildSecret(SecretKey secretKey) {
            try {
                Key[] keys = kdfAlgorithm.deriveKeys(secretKey, null, header, macAlgorithm, encAlgorithm, null);
                return build(keys[0], keys[1]);
            } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
            }
        }

        private Florentine build(Key macKey, Key encKey) throws GeneralSecurityException {
            var mac = Mac.getInstance(macAlgorithm.getMacAlgorithm());
            mac.init(macKey);

            var tag = mac.doFinal(encodeLength(contents.size() + 1));
            Iterator<Packet> packets = contents.iterator();
            Packet packet = new Packet(PacketType.HEADER, header.toString());

            for (; packets.hasNext(); packet = packets.next()) {
                mac.init(new SecretKeySpec(tag, 0, macAlgorithm.getKeySizeBytes(), macAlgorithm.getKeyAlgorthm()));
                mac.update((byte) packet.packetType.ordinal());
                mac.update(encodeLength(packet.content.length));
                mac.update(packet.content);
                tag = mac.doFinal();

                if (packet.packetType.isEncrypted()) {
                    var cipher = encAlgorithm.getCipher(Cipher.ENCRYPT_MODE, encKey, tag);
                    cipher.doFinal(packet.content, 0, packet.content.length, packet.content);
                }
            }

            return new Florentine(this, tag);
        }
    }

    private static String randomString() {
        var buffer = new byte[20];
        SECURE_RANDOM.nextBytes(buffer);
        return BASE64URL_ENCODER.encodeToString(buffer);
    }

    private enum PacketType {
        HEADER,
        PUBLIC,
        SECRET,
        CAVEAT;

        boolean isEncrypted() {
            return this == SECRET;
        }
    }

    private static class Packet {
        private final PacketType packetType;
        private final byte[] content;

        Packet(PacketType packetType, byte[] content) {
            this.packetType = packetType;
            this.content = content;
        }

        Packet(PacketType packetType, String content) {
            this(packetType, content.getBytes(UTF_8));
        }
    }
}
