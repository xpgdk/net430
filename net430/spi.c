#include <msp430.h>
#include <stdint.h>
#include "spi.h"

void spi_init(void) {
	UCB0CTL1 = UCSWRST;
	UCB0CTL0 = UCCKPH | UCMSB | UCMST | UCMODE_0 | UCSYNC;
	UCB0CTL1 |= UCSSEL_2;

	UCB0BR0 = 1;
	UCB0BR1 = 0x0;

	P1SEL |= BIT5 | BIT6 | BIT7;
	P1SEL2 |= BIT5 | BIT6 | BIT7;

	UCB0CTL1 &= ~UCSWRST;
}

uint8_t spi_send(uint8_t b) {
	while (!(UC0IFG & UCB0TXIFG))
		;

	UCB0TXBUF = b;

	while (!(UC0IFG & UCB0RXIFG))
		;

	return UCB0RXBUF;
}
