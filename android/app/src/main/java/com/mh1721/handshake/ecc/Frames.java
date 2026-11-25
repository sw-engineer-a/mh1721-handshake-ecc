package com.mh1721.handshake.ecc;

import java.io.IOException;
import java.util.Arrays;

/** Command, 16-bit big-endian length, payload. Status 0 means success. */
final class Frames {
    static final int HELLO = 0x01;
    static final int OPEN = 0x02;

    private Frames() {
    }

    static byte[] request(int command, byte[] payload) {
        int length = payload == null ? 0 : payload.length;
        byte[] frame = new byte[3 + length];
        frame[0] = (byte) command;
        frame[1] = (byte) (length >> 8);
        frame[2] = (byte) length;
        if (length > 0) {
            System.arraycopy(payload, 0, frame, 3, length);
        }
        return frame;
    }

    static final class PublicKey {
        final byte[] point;
        final byte[] curve;

        PublicKey(byte[] point, byte[] curve) {
            this.point = point;
            this.curve = curve;
        }
    }

    static PublicKey parsePublic(byte[] payload) throws IOException {
        int offset = 0;
        int pointLength = readLength(payload, offset);
        offset += 2;
        byte[] point = readBlock(payload, offset, pointLength);
        offset += pointLength;
        int curveLength = readLength(payload, offset);
        offset += 2;
        byte[] curve = readBlock(payload, offset, curveLength);
        offset += curveLength;
        if (offset != payload.length) {
            throw new IOException("public key has extra bytes");
        }
        return new PublicKey(point, curve);
    }

    private static int readLength(byte[] payload, int offset) throws IOException {
        if (payload == null || offset + 2 > payload.length) {
            throw new IOException("public key is too short");
        }
        return ((payload[offset] & 0xff) << 8) | (payload[offset + 1] & 0xff);
    }

    private static byte[] readBlock(byte[] payload, int offset, int length) throws IOException {
        if (length <= 0 || offset + length > payload.length) {
            throw new IOException("public key block does not fit");
        }
        return Arrays.copyOfRange(payload, offset, offset + length);
    }
}
