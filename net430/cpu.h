#include "config.h"
#include <msp430.h>

void delayMs(uint16_t ms);

static void
cpu_init(void) {
	WDTCTL = WDTPW + WDTHOLD; // Stop watchdog timer

	/* Set proper CPU clock speed */
	DCOCTL = 0;
#if CPU_FREQ == 1
    BCSCTL1 = CALBC1_1MHZ;
    DCOCTL = CALDCO_1MHZ;
#elif CPU_FREQ == 8
    BCSCTL1 = CALBC1_8MHZ;
    DCOCTL = CALDCO_8MHZ;
#elif CPU_FREQ == 12
    BCSCTL1 = CALBC1_12MHZ
    DCOCTL = CALDCO_12HZ;
#elif CPU_FREQ == 16
    BCSCTL1 = CALBC1_16MHZ;
    DCOCTL = CALDCO_16MHZ;
#else
#error "Unsupported CPU frequency"
#endif
}

/* Spends 3 * n cycles */
__inline__ static void delay_cycles(register unsigned int n) {
	__asm__ __volatile__ (
			"1: \n"
			" dec	%[n] \n"
			" jne	1b \n"
			: [n] "+r"(n));
}
