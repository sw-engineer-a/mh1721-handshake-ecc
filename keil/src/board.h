#ifndef BOARD_H
#define BOARD_H

#include <stdint.h>

void board_write(const uint8_t *data, int len);
int board_get_byte(void);

#endif
