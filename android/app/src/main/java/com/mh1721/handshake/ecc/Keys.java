package com.mh1721.handshake.ecc;

/**
 * NIST P-256 sample. The scalar and public point are the RFC 6979 appendix A.2.5 key pair.
 * The ephemeral scalar is the RFC 6979 SHA-256 nonce for "sample".
 */
final class Keys {
    static final String SCALAR =
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
    static final String PUBLIC_X =
            "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
    static final String PUBLIC_Y =
            "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
    /** TLS supported group 23, secp256r1. */
    static final String CURVE = "0017";
    static final String EPHEMERAL =
            "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60";
    static final String EPHEMERAL_X =
            "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716";
    static final String EPHEMERAL_Y =
            "34A7E72C423213443152C82DF94FE0F6851BF894FD91C64B19555346093FF492";
    /** ASCII "MH1721 ECC handshake block demo." */
    static final String PLAIN =
            "4D4831373231204543432068616E647368616B6520626C6F636B2064656D6F2E";
    static final String CIPHER =
            "CC50B151BB954B461CD04F547A82485D8E045D66D8A0831A47E912D300B63009";

    private Keys() {
    }
}
