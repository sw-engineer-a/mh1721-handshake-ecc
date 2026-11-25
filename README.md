# MH1721 ECC handshake

Two separate projects that use one NIST P-256 key instead of the 512-bit RSA key:

| Folder | What it is |
|---|---|
| `keil` | Keil µVision 5 project. Open `MH1721_Handshake_Ecc.uvprojx`. |
| `android` | Android app. Open this folder in Android Studio. |

The curve is NIST P-256, also called secp256r1. The private scalar `d` and the public point `Q = d * G` are the key pair from RFC 6979 appendix A.2.5. A coordinate is 32 bytes. The public point on the wire is the 65-byte uncompressed form `04 || x || y`. The curve id is the TLS supported-group value `00 17`.

A block is 32 bytes. The phone picks an ephemeral scalar `k` and sends `R = k * G` with the ciphertext. The shared secret is the x coordinate of `k * Q`, which is the same point as `d * R`. The mask is SHA-256 of that 32-byte coordinate, and the ciphertext is the block XOR the mask. There is no MAC. The sample ephemeral scalar is the RFC 6979 SHA-256 nonce for the message `sample`, so the x coordinate of `R` is the `r` value published in that appendix.

The bytes live in `keil/src/key.h` and `android/.../Keys.java`.

| Value | Meaning | Keil | Android |
|---|---|---|---|
| `d` | private scalar, 32 bytes | `ECC_D` | `Keys.SCALAR` |
| `Q` | public point, 65 bytes `04 \|\| x \|\| y` | `ECC_QX`, `ECC_QY` | `Keys.PUBLIC_X`, `Keys.PUBLIC_Y` |
| curve id | TLS group secp256r1, `0017` | `ECC_CURVE` | `Keys.CURVE` |
| `k` | sample ephemeral scalar | `ECC_K` | `Keys.EPHEMERAL` |
| `R` | `k * G` | `ECC_RX`, `ECC_RY` | `Keys.EPHEMERAL_X`, `Keys.EPHEMERAL_Y` |
| block | 32-byte plaintext | `ECC_PLAIN` | `Keys.PLAIN` |
| ciphertext | block XOR SHA-256(shared x) | `ECC_CIPHER` | `Keys.CIPHER` |

## Keil

Select the Simulator target. In Options for Target, Debug, choose Use Simulator. Build and run. View, Serial Windows, Debug (printf) Viewer should show:

```text
MH1721 ECC handshake
self-test ok
waiting for the phone
```

The self-test checks SHA-256("abc"), checks that `d * G` and `k * G` match the stored points, checks that `k * Q` and `d * R` share an x coordinate, checks the sample ciphertext, then opens that ciphertext with `d`.

The image is sized for the MH1721: 256 KB flash at `0x00000000` and 16 KB RAM at `0x20000000`. The stack is 6 KB. A build writes `Objects/MH1721_Handshake_Ecc.hex`.

Keil Download still cannot program the chip. The target has no MH1721 flash algorithm. MegaHunt’s boot tool writes that hex over the boot UART (GPIO0 receive, GPIO1 transmit) or the boot SPI pins. The public brief does not publish the UART register addresses, so `board_get_byte` and `board_write` remain the byte link in `board.c`. Each frame is one command or status byte, a 16-bit big-endian length, then that many payload bytes. Status 0 means success.

| Command | Value | Phone sends | Firmware returns |
|---|---|---|---|
| Hello | `0x01` | empty | 65-byte public point, then the 2-byte curve id `0017` |
| Open | `0x02` | 65-byte ephemeral point, then the 32-byte ciphertext | 32-byte plaintext |

Each Hello field is a 16-bit big-endian length followed by the bytes. Open is fixed at 97 bytes: `04 || Rx || Ry || ciphertext`. Hello comes first. The phone checks the point and the curve id, and only then sends Open. Open before Hello returns status 4 and no plaintext. After Hello, Open multiplies the ephemeral point by `d` and returns the plaintext.

ARM Compiler 6 is required. P-256 and SHA-256 are in `keil/src` with the rest of the firmware.

## Android

**Try on this phone** checks `d * G` against the stored public point, seals the sample block with the sample scalar, and checks the ephemeral point, the ciphertext, and the opened plaintext. It also seals the same block with a fresh scalar and opens that.

**Handshake with MH1721** asks the board for its public point and checks the 65 bytes and the curve id `0017`. The open payload is sent only after that check. The board returns the plaintext, and the phone checks it against the block it sealed. The board must speak the frames above on a USB bulk in/out pair. Connect it with a USB OTG adapter.
