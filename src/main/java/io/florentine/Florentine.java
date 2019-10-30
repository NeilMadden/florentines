package io.florentine;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;

public class Florentine {
    private static final Base64.Encoder BASE64_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder BASE64_DECODER = Base64.getUrlDecoder();

    private final List<Packet> packets;
    private byte[] tag;
    private byte minNextType;

    Florentine(List<Packet> packets, byte[] tag) {
        this.packets = requireNonNull(packets);
        this.tag = requireNonNull(tag);
        minNextType = (byte) packets.stream().mapToInt(packet -> packet.type.id).max().orElse(0);
    }

    public static Key generateKey() {
        return new SecretKeySpec(Crypto.randomBytes(32), Crypto.MAC_ALGORITHM);
    }

    public static Florentine create(Key rootKey, JSONObject header, byte[] identifier) {
        var headerPacket = new Packet(PacketType.HEADER, header.toString().getBytes(UTF_8));
        byte[] tag = Crypto.hmac(rootKey, headerPacket.type.id, headerPacket.data);
        return new Florentine(new ArrayList<>(Collections.singletonList(headerPacket)), tag).identifier(identifier);
    }

    public static Florentine create(Key rootKey, JSONObject header) {
        return create(rootKey, header, Crypto.randomBytes(20));
    }

    private Florentine addPacket(Packet packet) {
        if (packet.type.id < minNextType) {
            throw new IllegalStateException(
                    "Cannot add packet of type " + packet + " after " + lastPacket());
        }
        if (packet.type == PacketType.RESERVED_ENC_KEY) {
            throw new IllegalArgumentException("Cannot add packet with reserved type");
        }
        minNextType = packet.type.id;

        byte[] oldTag = this.tag;
        byte[] newTag = Crypto.hmac(oldTag, packet.type.id, packet.data);
        if (packet.type == PacketType.SECRET) {
            byte[] encKey = Crypto.hmac(oldTag, PacketType.RESERVED_ENC_KEY.id,
                    Crypto.ENC_ALGORITHM.getBytes(US_ASCII));
            packet.siv = Crypto.encrypt(encKey, newTag, packet.data);
        }
        packets.add(packet);
        Arrays.fill(oldTag, (byte) 0);
        this.tag = Arrays.copyOf(newTag, 16);
        return this;
    }

    public JSONObject header() {
        assert packets.size() > 0;
        assert packets.get(0).type == PacketType.HEADER;
        return new JSONObject(new String(packets.get(0).data, UTF_8));
    }

    public byte[] identifier() {
        assert packets.size() > 1;
        assert packets.get(1).type == PacketType.IDENTIFIER;
        return packets.get(1).data.clone();
    }

    boolean verifySignature(Key authKey) {
        var key = authKey;
        byte[] tag = null;
        for (var packet : packets) {
            var data = packet.data;
            if (packet.type == PacketType.SECRET) {
                byte[] encKey = Crypto.hmac(tag, PacketType.RESERVED_ENC_KEY.id,
                        Crypto.ENC_ALGORITHM.getBytes(US_ASCII));
                data = Crypto.decrypt(encKey, packet.siv, packet.data);
            }
            tag = Arrays.copyOf(Crypto.hmac(key, packet.type.id, data), 16);
            key = new SecretKeySpec(tag, Crypto.MAC_ALGORITHM);
        }
        return MessageDigest.isEqual(tag, this.tag);
    }

    public void serialize(OutputStream out) throws IOException {
        DataOutputStream dataOutputStream = new DataOutputStream(out);
        for (var packet : packets) {
            packet.writeTo(dataOutputStream);
        }
        new Packet(PacketType.SIGNATURE, tag).writeTo(dataOutputStream);
    }

    public String serialize() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(BASE64_ENCODER.wrap(baos))) {
            serialize(out);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return baos.toString(US_ASCII);
    }

    public static Florentine parse(InputStream in) throws IOException {
        var packets = new ArrayList<Packet>();

        DataInputStream dataInputStream = new DataInputStream(in);
        var header = Packet.readFrom(dataInputStream);
        if (header.type != PacketType.HEADER) {
            throw new IllegalArgumentException("Missing header");
        }
        packets.add(header);
        var identifier = Packet.readFrom(dataInputStream);
        if (identifier.type != PacketType.IDENTIFIER) {
            throw new IllegalArgumentException("Missing identifier");
        }
        packets.add(identifier);

        int minType = PacketType.IDENTIFIER.id + 1;
        var packet = Packet.readFrom(dataInputStream);
        while (packet.type != PacketType.SIGNATURE) {
            if (packet.type.id < minType) {
                throw new IllegalArgumentException("Unexpected packet type");
            }
            packets.add(packet);
            minType = packet.type.id;
            packet = Packet.readFrom(dataInputStream);
        }

        return new Florentine(packets, packet.data);
    }

    public static Florentine parse(String input) {
        try (InputStream in = BASE64_DECODER.wrap(new ByteArrayInputStream(input.getBytes(US_ASCII)))) {
            Florentine florentine = parse(in);
            if (in.read() != -1) {
                throw new IllegalArgumentException("Extra data after end of token");
            }
            return florentine;
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private Packet lastPacket() {
        return packets.get(packets.size() - 1);
    }

    private Florentine identifier(byte[] identifier) {
        addPacket(new Packet(PacketType.IDENTIFIER, identifier.clone()));
        minNextType++;
        return this;
    }

    public Florentine addPublic(byte[] data) {
        return addPacket(new Packet(PacketType.PUBLIC, data.clone()));
    }

    public Florentine addPublic(String data) {
        return addPublic(data.getBytes(UTF_8));
    }

    public Florentine addPublic(JSONObject publicClaims) {
        return addPublic(publicClaims.toString());
    }

    public Florentine addSecret(byte[] data) {
        return addPacket(new Packet(PacketType.SECRET, data.clone()));
    }

    public Florentine addSecret(String secret) {
        return addSecret(secret.getBytes(UTF_8));
    }

    public Florentine addSecret(JSONObject secretClaims) {
        return addSecret(secretClaims.toString());
    }

    public Florentine addCaveat(JSONObject caveat) {
        return addPacket(new Packet(PacketType.CAVEAT, caveat.toString().getBytes(UTF_8)));
    }

    private enum PacketType {
        HEADER(0),
        IDENTIFIER(10),
        PUBLIC(20),
        SECRET(30),
        CAVEAT(40),
        SIGNATURE(100),
        RESERVED_ENC_KEY(255);
        final byte id;

        PacketType(int id) {
            this.id = (byte) id;
        }

        static PacketType forByte(byte id) {
            return Arrays.stream(values())
                    .filter(type -> type.id == id)
                    .findAny()
                    .orElseThrow(() -> new IllegalArgumentException("Unknown packet type: " + id));
        }
    }

    static class Packet {
        final PacketType type;
        final byte[] data;
        byte[] siv;

        Packet(PacketType type, byte[] data) {
            this.type = type;
            this.data = data;
        }

        void writeTo(DataOutputStream out) throws IOException {
            out.writeByte(type.id);
            out.writeShort(data.length);
            out.write(data);
            if (type == PacketType.SECRET) {
                out.write(siv);
            }
        }

        static Packet readFrom(DataInputStream in) throws IOException {
            PacketType type = PacketType.forByte(in.readByte());
            int length = in.readUnsignedShort();
            byte[] data = in.readNBytes(length);
            var packet = new Packet(type, data);
            if (type == PacketType.SECRET) {
                packet.siv = in.readNBytes(16);
            }
            return packet;
        }

        @Override
        public String toString() {
            return "Packet{type=" + type + '}';
        }
    }
}
