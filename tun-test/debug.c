#include <debug.h>
#include <stdio.h>

void debug_out_init(void) {
}

void debug_puts(const char *str) {
	printf("%s", str);
}

void debug_puthex(uint16_t value) {
	printf("%X", value);
}

void debug_nl(void) {
	printf("\n");
}
