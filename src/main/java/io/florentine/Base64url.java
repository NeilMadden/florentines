package io.florentine;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.Base64;

final class Base64url {
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    static String encode(byte[] value) {
        return ENCODER.encodeToString(value);
    }

    static byte[] decode(String value) {
        return DECODER.decode(value);
    }

    static OutputStream wrap(OutputStream out) {
        return ENCODER.wrap(out);
    }

    static InputStream wrap(InputStream in) {
        return DECODER.wrap(in);
    }

    private Base64url() {}
}
