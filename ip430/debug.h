#ifndef DEBUG_H_
#define DEBUG_H_

#include <stdint.h>

void debug_out_init(void);
void debug_puts(const char *str);
void debug_puthex(uint16_t value);
void debug_nl(void);

#define GET_SP(targetVar) __asm__("mov r1, %0" : "=r" (targetVar));
#define PRINT_SP(loc) do { register uint16_t sp; GET_SP(sp); debug_puts("SP: "); debug_puts(loc); debug_puthex(sp); debug_nl();} while(0)

#endif
