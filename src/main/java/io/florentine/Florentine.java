package io.florentine;


import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.json.JSONObject;

public class Florentine {
    static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final MacAlgorithm macAlgorithm;
    private final EncAlgorithm encAlgorithm;

    private final List<Packet> packets;
    private byte[] tag;

    Florentine(MacAlgorithm macAlgorithm, EncAlgorithm encAlgorithm, List<Packet> packets, byte[] tag) {
        this.macAlgorithm = macAlgorithm;
        this.encAlgorithm = encAlgorithm;
        this.packets = packets;
        this.tag = tag;

        assert packets.get(0) instanceof Header;
    }

    public static Builder builder() {
        return new Builder();
    }

    public JSONObject getHeader() {
        return ((Header) packets.get(0)).header;
    }

    public Florentine addCaveat(JSONObject caveat) {
        add(new Caveat(caveat));
        return this;
    }

    private byte[] add(Packet packet) {
        var newTag = macAlgorithm.authenticate(tag, packet);
        this.packets.add(packet);
        this.tag = Arrays.copyOf(newTag, macAlgorithm.getTagLength());
        return newTag;
    }

    public Florentine copy() {
        return new Florentine(macAlgorithm, encAlgorithm, new ArrayList<>(packets), tag.clone());
    }

    public String serialize() {
        try (var buffer = new ByteArrayOutputStream();
             var out = new DataOutputStream(buffer)) {

            for (var packet : packets) {
                packet.write(out);
            }

            var tagPacket = new Tag(tag);
            tagPacket.write(out);
            out.flush();

            return Base64url.encode(buffer.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static Florentine deserialize(MacAlgorithm macAlgorithm, EncAlgorithm encAlgorithm, String token) {
        try (var in = new DataInputStream(new ByteArrayInputStream(Base64url.decode(token)))) {

            var header = expect(in, Header.TYPE);

            var len = ((Header) header).header.getInt("len");
            var packets = new ArrayList<Packet>(len + 1);
            packets.add(header);

            for (int i = 0; i < len; ++i) {
                var packet = expect(in, Public.TYPE, Secret.TYPE);
                packets.add(packet);

                if (packet.type == Secret.TYPE) {
                    // Next packet must be the SIV
                    var sivPacket = expect(in, Siv.TYPE);
                    ((Secret) packet).siv = sivPacket.bytes;
                    packets.add(sivPacket);
                }
            }

            var packet = expect(in, Caveat.TYPE, Tag.TYPE);
            while (packet.type == Caveat.TYPE) {
                packets.add(packet);
                packet = expect(in, Caveat.TYPE, Tag.TYPE);
            }

            if (packet.type != Tag.TYPE) {
                throw new IllegalArgumentException("missing authentication tag");
            }

            var tag = packet.bytes;
            if (tag.length != macAlgorithm.getTagLength()) {
                throw new IllegalArgumentException("invalid authentication tag");
            }

            if (in.read() != -1) {
                throw new IllegalArgumentException("extra data after tag");
            }

            return new Florentine(macAlgorithm, encAlgorithm, packets, tag);
        } catch (IOException e) {
            throw new IllegalArgumentException("invalid florentine", e);
        }
    }

    public boolean verify(MessageKeys msgKeys) {
        if (msgKeys.getMacAlgorithm() != macAlgorithm || msgKeys.getEncAlgorithm() != encAlgorithm) {
            throw new IllegalArgumentException("algorithm mismatch");
        }

        var packets = new ArrayList<>(this.packets);
        packets.add(new Tag(tag));

        var header = packets.get(0);
        var computed = msgKeys.authenticate(header);

        var valid = true;
        for (var packet : packets.subList(1, packets.size())) {
            valid &= packet.process(msgKeys, computed);
            computed = macAlgorithm.authenticate(computed, packet);
        }

        if (!valid) {
            // Tag or SIV validation failed, so blow away all data to avoid leaking any secrets
            for (var packet : packets) {
                Arrays.fill(packet.bytes, (byte)0);
            }
        }

        return valid;
    }

    private static Packet expect(DataInputStream in, byte...packetTypes) throws IOException {
        var packet = readPacket(in);
        if (packet == null) {
            throw new EOFException("unexpected end of input");
        }
        for (byte allowed : packetTypes) {
            if (packet.type == allowed) {
                return packet;
            }
        }
        throw new IllegalArgumentException("unexpected packet type");
    }

    private static Packet readPacket(DataInputStream in) throws IOException {
        var type = in.read();
        if (type == -1) {
            return null;
        }

        var len = (in.read() << 8) | in.read();
        if (len < 0 || len > 65535) {
            throw new IllegalArgumentException("invalid packet length: " + len);
        }
        var bytes = new byte[len];
        if (in.read(bytes) != bytes.length) {
            throw new IllegalArgumentException("invalid packet data");
        }
        Packet packet;
        switch (type) {
        case Header.TYPE:
            packet = new Header(new JSONObject(new String(bytes, UTF_8)));
            break;
        case Public.TYPE:
            packet = new Public(bytes);
            break;
        case Secret.TYPE:
            packet = new Secret(bytes);
            break;
        case Caveat.TYPE:
            packet = new Caveat(new JSONObject(new String(bytes, UTF_8)));
            break;
        case Tag.TYPE:
            packet = new Tag(bytes);
            break;
        case Siv.TYPE:
            packet = new Siv(bytes);
            break;
        default:
            throw new IllegalArgumentException("invalid packet type: " + type);
        }

        return packet;
    }

    public static class Builder {
        private final JSONObject header = new JSONObject()
                .put("typ", "florentine")
                .put("uid", random());

        private final List<Packet> packets = new ArrayList<>();

        public Builder header(String key, Object value) {
            header.put(key, value);
            return this;
        }

        public Builder type(String type) {
            return header("typ", type);
        }

        public Builder contentType(String contentType) {
            return header("cty", contentType);
        }

        public Builder keyId(String keyId) {
            return header("kid", keyId);
        }

        public Builder addPublic(byte[] content) {
            packets.add(new Public(content));
            return this;
        }

        public Builder addPublic(String content) {
            return addPublic(content.getBytes(UTF_8));
        }

        public Builder addPublic(JSONObject content) {
            return addPublic(content.toString());
        }

        public Builder addSecret(byte[] content) {
            packets.add(new Secret(content));
            return this;
        }

        public Builder addSecret(String content) {
            return addSecret(content.getBytes(UTF_8));
        }

        public Builder addSecret(JSONObject content) {
            return addSecret(content.toString());
        }

        public Florentine build(MessageKeys keys) {
            requireNonNull(keys, "MessageKeys");

            this.header.put("len", packets.size());
            var header = new Header(this.header);
            var tag = keys.authenticate(header);

            var florentine = new Florentine(keys.getMacAlgorithm(), keys.getEncAlgorithm(),
                    new ArrayList<>(List.of(header)), tag);

            for (var packet : packets) {
                tag = florentine.add(packet);
                if (packet.type == Secret.TYPE) {
                    var siv = keys.encrypt(((Secret) packet), tag);
                    florentine.add(new Siv(siv));
                }
            }

            return florentine;
        }

        private static String random() {
            var buffer = new byte[20];
            SECURE_RANDOM.nextBytes(buffer);
            return Base64url.encode(buffer);
        }
    }

    abstract static class Packet {
        final byte type;
        final byte[] bytes;

        Packet(byte type, byte[] bytes) {
            if (bytes.length > 65535) {
                throw new IllegalArgumentException("Packet too large: max 65535 bytes");
            }
            this.type = type;
            this.bytes = bytes;
        }

        void write(DataOutput out) throws IOException {
            out.write(type);
            out.writeShort(bytes.length);
            out.write(bytes);
        }

        boolean process(MessageKeys keys, byte[] tag) {
            return true;
        }
    }

    static class Header extends Packet {
        static final byte TYPE = 'H';

        final JSONObject header;

        Header(JSONObject header) {
            super(TYPE, header.toString().getBytes(UTF_8));
            this.header = header;
        }
    }

    static class Public extends Packet {
        static final byte TYPE = 'P';
        Public(byte[] content) {
            super(TYPE, content);
        }
    }

    static class Secret extends Packet {
        static final byte TYPE = 'S';

        byte[] siv;

        Secret(byte[] content) {
            super(TYPE, content);
        }

        @Override
        boolean process(MessageKeys keys, byte[] tag) {
            keys.decrypt(this);
            return true;
        }
    }

    static class Caveat extends Packet {
        static final byte TYPE = 'C';

        final JSONObject caveat;

        Caveat(JSONObject caveat) {
            super(TYPE, caveat.toString().getBytes(UTF_8));
            this.caveat = caveat;
        }
    }

    static class Tag extends Packet {
        static final byte TYPE = 'T';

        Tag(byte[] tag) {
            super(TYPE, tag);
        }

        @Override
        boolean process(MessageKeys keys, byte[] computed) {
            return MessageDigest.isEqual(bytes, Arrays.copyOf(computed, bytes.length));
        }
    }

    static class Siv extends Packet {
        static final byte TYPE = 'I';

        Siv(byte[] siv) {
            super(TYPE, siv);
        }

        @Override
        boolean process(MessageKeys keys, byte[] tag) {
            var computed = keys.getEncAlgorithm().getSiv(tag);
            return MessageDigest.isEqual(bytes, computed);
        }
    }
}
