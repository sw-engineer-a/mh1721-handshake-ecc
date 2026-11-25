package com.mh1721.handshake.ecc;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * P-256 scalar multiplication and the raw handshake seal.
 * The shared secret is the x coordinate of k * Q. The mask is SHA-256 of that
 * coordinate, and the ciphertext is the 32-byte block XOR the mask.
 */
final class EccBox {
    static final int BLOCK = 32;
    static final int SCALAR = 32;
    static final int POINT = 65;
    static final int OPEN = POINT + BLOCK;

    private static final BigInteger P = new BigInteger(
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    private static final BigInteger B = new BigInteger(
            "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
    private static final BigInteger N = new BigInteger(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final Point G = new Point(
            new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
            new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16));

    private static final SecureRandom RANDOM = new SecureRandom();

    private EccBox() {
    }

    static byte[] plain() {
        return hex(Keys.PLAIN);
    }

    static byte[] cipher() {
        return hex(Keys.CIPHER);
    }

    static byte[] sampleScalar() {
        return hex(Keys.EPHEMERAL);
    }

    static byte[] publicPoint() {
        return uncompressed(new Point(new BigInteger(1, hex(Keys.PUBLIC_X)),
                new BigInteger(1, hex(Keys.PUBLIC_Y))));
    }

    static byte[] samplePoint() {
        return uncompressed(new Point(new BigInteger(1, hex(Keys.EPHEMERAL_X)),
                new BigInteger(1, hex(Keys.EPHEMERAL_Y))));
    }

    static byte[] curve() {
        return hex(Keys.CURVE);
    }

    /** Q = d * G, uncompressed. */
    static byte[] derivedPublic() {
        return uncompressed(multiply(new BigInteger(1, hex(Keys.SCALAR)), G));
    }

    static byte[] encrypt(byte[] block, byte[] scalar) {
        if (block == null || block.length != BLOCK || scalar == null || scalar.length != SCALAR) {
            throw new IllegalArgumentException("block is 32 bytes and the scalar is 32 bytes");
        }
        BigInteger k = new BigInteger(1, scalar);
        if (k.signum() <= 0 || k.compareTo(N) >= 0) {
            throw new IllegalArgumentException("scalar is outside 1..n-1");
        }
        Point q = new Point(new BigInteger(1, hex(Keys.PUBLIC_X)), new BigInteger(1, hex(Keys.PUBLIC_Y)));
        Point r = multiply(k, G);
        Point shared = multiply(k, q);
        byte[] out = new byte[OPEN];
        byte[] point = uncompressed(r);
        System.arraycopy(point, 0, out, 0, POINT);
        System.arraycopy(xor(block, mask(shared.x)), 0, out, POINT, BLOCK);
        return out;
    }

    static byte[] seal(byte[] block) {
        byte[] scalar = new byte[SCALAR];
        BigInteger k;
        do {
            RANDOM.nextBytes(scalar);
            k = new BigInteger(1, scalar);
        } while (k.signum() <= 0 || k.compareTo(N) >= 0);
        return encrypt(block, scalar);
    }

    static byte[] decrypt(byte[] payload) {
        if (payload == null || payload.length != OPEN) {
            throw new IllegalArgumentException("open payload is 97 bytes");
        }
        Point r = decode(payload);
        Point shared = multiply(new BigInteger(1, hex(Keys.SCALAR)), r);
        if (shared == null) {
            throw new IllegalArgumentException("shared point is infinity");
        }
        return xor(copy(payload, POINT, BLOCK), mask(shared.x));
    }

    private static byte[] mask(BigInteger x) {
        try {
            return java.security.MessageDigest.getInstance("SHA-256").digest(fixed(x, 32));
        } catch (java.security.NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 is missing", error);
        }
    }

    private static Point multiply(BigInteger scalar, Point point) {
        Point result = null;
        Point addend = point;
        for (int bit = scalar.bitLength() - 1; bit >= 0; bit--) {
            if (result != null) {
                result = twice(result);
            }
            if (scalar.testBit(bit)) {
                result = add(result, addend);
            }
        }
        return result;
    }

    private static Point add(Point p, Point q) {
        if (p == null) {
            return q;
        }
        if (q == null) {
            return p;
        }
        if (p.x.equals(q.x)) {
            if (p.y.add(q.y).mod(P).signum() == 0) {
                return null;
            }
            return twice(p);
        }
        BigInteger slope = q.y.subtract(p.y).mod(P)
                .multiply(q.x.subtract(p.x).mod(P).modInverse(P)).mod(P);
        return slopePoint(slope, p, q.x);
    }

    private static Point twice(Point p) {
        if (p == null || p.y.signum() == 0) {
            return null;
        }
        BigInteger slope = THREE.multiply(p.x.modPow(TWO, P)).add(P.subtract(THREE)).mod(P)
                .multiply(TWO.multiply(p.y).mod(P).modInverse(P)).mod(P);
        return slopePoint(slope, p, p.x);
    }

    private static Point slopePoint(BigInteger slope, Point p, BigInteger x2) {
        BigInteger x3 = slope.pow(2).subtract(p.x).subtract(x2).mod(P);
        BigInteger y3 = slope.multiply(p.x.subtract(x3)).subtract(p.y).mod(P);
        return new Point(x3, y3);
    }

    private static Point decode(byte[] payload) {
        if (payload[0] != 0x04) {
            throw new IllegalArgumentException("ephemeral point is not uncompressed");
        }
        BigInteger x = new BigInteger(1, copy(payload, 1, 32));
        BigInteger y = new BigInteger(1, copy(payload, 33, 32));
        if (x.compareTo(P) >= 0 || y.compareTo(P) >= 0) {
            throw new IllegalArgumentException("ephemeral point is outside the field");
        }
        Point point = new Point(x, y);
        if (!onCurve(point)) {
            throw new IllegalArgumentException("ephemeral point is not on P-256");
        }
        return point;
    }

    private static boolean onCurve(Point point) {
        BigInteger left = point.y.modPow(TWO, P);
        BigInteger right = point.x.modPow(THREE, P).subtract(THREE.multiply(point.x)).add(B).mod(P);
        return left.equals(right);
    }

    private static byte[] uncompressed(Point point) {
        if (point == null) {
            throw new IllegalArgumentException("point is infinity");
        }
        byte[] out = new byte[POINT];
        out[0] = 0x04;
        System.arraycopy(fixed(point.x, 32), 0, out, 1, 32);
        System.arraycopy(fixed(point.y, 32), 0, out, 33, 32);
        return out;
    }

    private static byte[] xor(byte[] block, byte[] mask) {
        byte[] out = new byte[BLOCK];
        for (int i = 0; i < BLOCK; i++) {
            out[i] = (byte) (block[i] ^ mask[i]);
        }
        return out;
    }

    private static byte[] fixed(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        int start = 0;
        int count = raw.length;
        if (count > 0 && raw[0] == 0) {
            start = 1;
            count--;
        }
        if (count > length) {
            throw new IllegalArgumentException("value does not fit in " + length + " bytes");
        }
        byte[] out = new byte[length];
        System.arraycopy(raw, start, out, length - count, count);
        return out;
    }

    private static byte[] copy(byte[] source, int offset, int length) {
        byte[] out = new byte[length];
        System.arraycopy(source, offset, out, 0, length);
        return out;
    }

    private static byte[] hex(String text) {
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static final class Point {
        final BigInteger x;
        final BigInteger y;

        Point(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }
    }
}
