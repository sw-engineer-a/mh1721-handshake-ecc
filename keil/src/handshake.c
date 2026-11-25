#include "board.h"
#include "ecc.h"

#define CMD_HELLO 0x01u
#define CMD_OPEN  0x02u

#define ST_OK         0u
#define ST_BAD        1u
#define ST_CRYPTO     2u
#define ST_LENGTH     3u
#define ST_NEED_HELLO 4u

static uint8_t payload[256];
static uint8_t reply[280];
static int greeted;

static void read_exact(uint8_t *dst, int len) {
    int i;
    for (i = 0; i < len; i++) {
        dst[i] = (uint8_t)board_get_byte();
    }
}

static void send_frame(uint8_t status, const uint8_t *data, int len) {
    uint8_t header[3];
    header[0] = status;
    header[1] = (uint8_t)((len >> 8) & 0xff);
    header[2] = (uint8_t)(len & 0xff);
    board_write(header, 3);
    if (len > 0 && data) {
        board_write(data, len);
    }
}

void handshake_loop(void) {
    for (;;) {
        uint8_t header[3];
        int len;
        int extra;
        read_exact(header, 3);
        len = ((int)header[1] << 8) | header[2];
        if (len > (int)sizeof(payload)) {
            extra = len;
            while (extra > 0) {
                int chunk = extra > (int)sizeof(payload) ? (int)sizeof(payload) : extra;
                read_exact(payload, chunk);
                extra -= chunk;
            }
            send_frame(ST_LENGTH, 0, 0);
            continue;
        }
        if (len > 0) {
            read_exact(payload, len);
        }
        if (header[0] == CMD_HELLO) {
            int n = ecc_public_block(reply, (int)sizeof(reply));
            if (n < 0) {
                send_frame(ST_CRYPTO, 0, 0);
            } else {
                greeted = 1;
                send_frame(ST_OK, reply, n);
            }
        } else if (header[0] == CMD_OPEN) {
            int n;
            if (!greeted) {
                send_frame(ST_NEED_HELLO, 0, 0);
                continue;
            }
            n = ecc_open(payload, len, reply, (int)sizeof(reply));
            if (n < 0) {
                send_frame(ST_CRYPTO, 0, 0);
            } else {
                send_frame(ST_OK, reply, n);
            }
        } else {
            send_frame(ST_BAD, 0, 0);
        }
    }
}
