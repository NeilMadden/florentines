package io.florentine;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.Mac;

import org.json.JSONObject;

public final class Florentine {
    private static final Base64.Encoder BASE64URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder BASE64URL_DECODER = Base64.getUrlDecoder();
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final JSONObject header;
    private final List<Packet> contents;
    private final List<Packet> caveats;

    private byte[] tag;
    private MacAlgorithm macAlgorithm;
    private EncAlgorithm encAlgorithm;

    Florentine(Builder builder, byte[] tag) {
        this.header = builder.header;
        this.contents = Collections.unmodifiableList(builder.contents);
        this.caveats = new ArrayList<>();
        this.tag = tag;
        this.macAlgorithm = builder.recipient.getMacAlgorithm();
        this.encAlgorithm = builder.recipient.getEncAlgorithm();
    }

    Florentine(JSONObject header, List<Packet> contents, List<Packet> caveats, byte[] tag) {
        this.header = header;
        this.contents = Collections.unmodifiableList(contents);
        this.caveats = caveats;
        this.tag = tag;
    }

    public static Builder builder() {
        return new Builder();
    }

    public Florentine withMacAlgorithm(MacAlgorithm macAlgorithm) {
        this.macAlgorithm = macAlgorithm;
        return this;
    }

    public Florentine withEncAlgorithm(EncAlgorithm encAlgorithm) {
        this.encAlgorithm = encAlgorithm;
        return this;
    }

    public Florentine addCaveat(JSONObject caveat) {
        if (macAlgorithm == null) {
            throw new IllegalStateException("Unknown MAC algorithm - call withMacAlgorithm() first");
        }
        var packet = new Packet(PacketType.CAVEAT, caveat.toString());
        this.tag = packet.authenticate(macAlgorithm.getMac(), this.tag);
        caveats.add(packet);
        return this;
    }

    public JSONObject getHeader() {
        return header;
    }

    public Florentine expiresAt(Instant expiryTime) {
        return addCaveat(new JSONObject().put("exp", expiryTime.getEpochSecond()));
    }

    public Florentine notBefore(Instant notBeforeTime) {
        return addCaveat(new JSONObject().put("nbf", notBeforeTime.getEpochSecond()));
    }

    public Florentine confirmationKey(JSONObject confirmationKey) {
        return addCaveat(new JSONObject().put("cnf", confirmationKey));
    }

    public static Florentine decode(String florentine) {
        try (var in = BASE64URL_DECODER.wrap(new ByteArrayInputStream(florentine.getBytes(UTF_8)))) {
            var packet = readPacket(in);
            if (packet == null || packet.packetType != PacketType.HEADER) {
                throw new IllegalArgumentException("missing header");
            }
            JSONObject header = new JSONObject(new String(packet.content, UTF_8));

            var length = header.getInt("len");
            var contents = new ArrayList<Packet>(length - 1);
            for (var i = 0; i < length - 1; ++i) {
                packet = readPacket(in);
                if (packet == null) {
                    throw new IllegalArgumentException("missing content packet");
                }
                if (packet.packetType != PacketType.PUBLIC && packet.packetType != PacketType.SECRET) {
                    throw new IllegalArgumentException("unexpected packet type while reading contents: " + packet.packetType);
                }
                contents.add(packet);
            }

            var caveats = new ArrayList<Packet>();
            packet = readPacket(in);

            while (packet != null) {
                if (packet.packetType == PacketType.MACTAG) {
                    break;
                }
                if (packet.packetType != PacketType.CAVEAT) {
                    throw new IllegalArgumentException("unexpected packet type while reading caveats: " + packet.packetType);
                }
                caveats.add(packet);
                packet = readPacket(in);
            }

            if (packet == null) {
                throw new IllegalArgumentException("missing authentication tag");
            }
            var tag = packet.content;

            return new Florentine(header, contents, caveats, tag);

        } catch (IOException | ArrayIndexOutOfBoundsException e) {
            throw new IllegalArgumentException("invalid florentine", e);
        }
    }

    public boolean verifySignature(FlorentineKey myKey, FlorentineKey senderKey) {
        this.macAlgorithm = myKey.getMacAlgorithm();
        this.encAlgorithm = myKey.getEncAlgorithm();

        try {
            var messageKeys = myKey.getKdfAlgorithm().deriveKeys(senderKey, myKey, header);
            var macKey = messageKeys.getMacKey();
            var encKey = messageKeys.getEncKey();

            var mac = macAlgorithm.getMac();
            mac.init(macKey);
            var tag = mac.doFinal(encodeLength(header.getInt("len")));

            for (var packet : allPackets()) {
                if (packet.packetType.isEncrypted()) {
                    if (packet.siv == null) {
                        throw new IllegalArgumentException("missing SIV for encrypted packet");
                    }
                    var cipher = encAlgorithm.getCipher(Cipher.DECRYPT_MODE, encKey, packet.siv);
                    cipher.doFinal(packet.content, 0, packet.content.length, packet.content);
                }

                tag = packet.authenticate(mac, tag);
            }

            return MessageDigest.isEqual(tag, this.tag);

        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private static Packet readPacket(InputStream in) throws IOException {
        var nextByte = in.read();
        if (nextByte == -1) {
            return null;
        }
        var packetType = PacketType.valueOf((byte) nextByte);
        var packetLength = in.read() | (in.read() << 8);
        if (packetLength < 0 || packetLength > 65535) {
            throw new IllegalArgumentException("invalid packet length");
        }
        var content = in.readNBytes(packetLength);
        if (content.length != packetLength) {
            throw new IOException("failed to read correctly sized packet");
        }
        byte[] siv = null;
        if (packetType.isEncrypted()) {
            var sivLen = in.read() | (in.read() << 8);
            if (sivLen < 0 || sivLen > 32) {
                throw new IllegalArgumentException("invalid siv length");
            }
            siv = in.readNBytes(sivLen);
            if (siv.length != sivLen) {
                throw new IOException("failed to read correctly sized SIV");
            }
        }
        var packet = new Packet(packetType, content);
        packet.siv = siv;
        return packet;
    }

    public void writeTo(OutputStream outputStream) throws IOException {
        try (var out = BASE64URL_ENCODER.wrap(new UncloseableOutputStream(outputStream))) {
            for (Packet packet : allPackets()) {
                out.write(packet.packetType.getPacketIndicator());
                out.write(encodeLength(packet.content.length));
                out.write(packet.content);
                if (packet.packetType.isEncrypted()) {
                    out.write(encodeLength(packet.siv.length));
                    out.write(packet.siv);
                }
            }

            out.write(PacketType.MACTAG.getPacketIndicator());
            out.write(encodeLength(tag.length));
            out.write(tag);
        }
    }

    private static class UncloseableOutputStream extends FilterOutputStream {
        UncloseableOutputStream(OutputStream out) {
            super(out);
        }

        @Override
        public void close() throws IOException {
            // Only flush, don't close
            super.flush();
        }
    }

    @Override
    public String toString() {
        try (var out = new ByteArrayOutputStream()) {
            writeTo(out);
            return new String(out.toByteArray(), US_ASCII);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private Iterable<Packet> allPackets() {
        var headerPacket = Collections.singleton(new Packet(PacketType.HEADER, header.toString()));
        return Utils.concat(headerPacket, contents, caveats);
    }

    private static byte[] encodeLength(int length) {
        if (length < 0 || length > 65535) {
            throw new IllegalArgumentException("length cannot be represented in 16 bits");
        }
        return ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort((short) length).array();
    }

    public static class Builder {
        private final JSONObject header = new JSONObject()
                .put("uid", randomString());
        private final List<Packet> contents = new ArrayList<>();

        private FlorentineKey recipient;
        private FlorentineKey sender;

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

        public Builder issuer(String issuer) {
            header.put("iss", issuer);
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

        public Builder to(FlorentineKey recipient) {
            this.recipient = recipient;
            header.put("kid", recipient.getKeyId());
            return this;
        }

        public Builder from(FlorentineKey sender) {
            this.sender = sender;
            if (recipient == null) {
                return to(sender);
            }
            return this;
        }

        public Florentine build() throws GeneralSecurityException {
            if (sender == null) { throw new IllegalStateException("no sender key specified"); }
            if (recipient == null) { throw new IllegalStateException("no recipient key specified"); }

            if (sender.getKdfAlgorithm() != recipient.getKdfAlgorithm()) {
                throw new IllegalStateException("sender and recipient use incompatible KDF algorithms");
            }

            var kdfAlgorithm = recipient.getKdfAlgorithm();
            var macAlgorithm = recipient.getMacAlgorithm();
            var encAlgorithm = recipient.getEncAlgorithm();

            var messageKeys = kdfAlgorithm.deriveKeys(sender, recipient, header);
            var macKey = messageKeys.getMacKey();
            var encKey = messageKeys.getEncKey();

            try {
                var mac = macAlgorithm.getMac();
                mac.init(macKey);
                var len = contents.size() + 1;
                header.put("len", len);

                var tag = mac.doFinal(encodeLength(len));
                var headerPacket = new Packet(PacketType.HEADER, header.toString());
                tag = headerPacket.authenticate(mac, tag);

                for (var packet : contents) {
                    tag = packet.authenticate(mac, tag);

                    if (packet.packetType.isEncrypted()) {
                        var cipher = encAlgorithm.getCipher(Cipher.ENCRYPT_MODE, encKey,
                                Arrays.copyOfRange(tag, 32, tag.length));
                        packet.siv = cipher.getIV();
                        cipher.doFinal(packet.content, 0, packet.content.length, packet.content);
                    }
                }

                return new Florentine(this, tag);
            } finally {
                Utils.destroyKeyMaterial(macKey, encKey);
            }
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
        CAVEAT,
        MACTAG;

        boolean isEncrypted() {
            return this == SECRET;
        }
        byte getPacketIndicator() {
            return (byte) name().charAt(0);
        }

        static PacketType valueOf(byte indicator) {
            for (var candidate : values()) {
                if (candidate.getPacketIndicator() == indicator) {
                    return candidate;
                }
            }
            throw new IllegalArgumentException("unknown packet type");
        }
    }

    private static class Packet {
        private final PacketType packetType;
        private final byte[] content;
        private byte[] siv;

        Packet(PacketType packetType, byte[] content) {
            this.packetType = packetType;
            this.content = content;
        }

        Packet(PacketType packetType, String content) {
            this(packetType, content.getBytes(UTF_8));
        }

        byte[] authenticate(Mac mac, byte[] oldTag) {
            var key = new DestroyableSecretKey(oldTag, 0, mac.getMacLength(), mac.getAlgorithm());
            try {
                mac.init(key);
                mac.update(packetType.getPacketIndicator());
                mac.update(encodeLength(content.length));
                mac.update(content);
                return mac.doFinal();
            } catch (InvalidKeyException e) {
                throw new IllegalStateException(e);
            } finally {
                Utils.destroyKeyMaterial(key);
            }
        }
    }
}
