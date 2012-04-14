#ifndef DEBUG_H_
#define DEBUG_H_

#include <stdint.h>

void debug_out_init(void);
void debug_puts(const char *str);
void debug_puthex(uint16_t value);
void debug_nl(void);

#endif
