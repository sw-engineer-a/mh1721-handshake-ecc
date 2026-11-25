#include "board.h"

/*
 * Byte link for the handshake frames.
 * The MH1721 boot UART is GPIO0 (receive) and GPIO1 (transmit). The public
 * brief does not publish the UART registers, so these functions keep the
 * bytes in RAM. In the simulator, set board_rx_byte and board_rx_ready to
 * inject a byte. Replies are stored in board_tx.
 */

volatile uint8_t board_rx_byte;
volatile uint8_t board_rx_ready;
volatile uint16_t board_tx_len;
volatile uint8_t board_tx[320];

void SystemInit(void) {
}

void board_write(const uint8_t *data, int len) {
    int i;
    if (!data || len <= 0) {
        return;
    }
    for (i = 0; i < len; i++) {
        if (board_tx_len < (uint16_t)sizeof(board_tx)) {
            board_tx[board_tx_len++] = data[i];
        }
    }
}

int board_get_byte(void) {
    while (!board_rx_ready) {
    }
    board_rx_ready = 0;
    return board_rx_byte;
}
