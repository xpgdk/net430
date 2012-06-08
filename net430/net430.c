#include <stdlib.h>

#include <msp430.h>

#include "net430.h"
#include "cpu.h"
#include "spi.h"
#include "enc28j60.h"
#include "uart.h"
#include "spi_mem.h"

#define TIME_STEP	5 //seconds

uint16_t timeValue = 0;

bool getRandomBit() {
	ADC10CTL1 |= INCH_5;
	ADC10CTL0 |= SREF_1 + ADC10SHT_1 + REFON + ADC10ON;
	ADC10CTL0 |= ENC + ADC10SC;
	while (ADC10CTL1 & ADC10BUSY)
		;
	return ADC10MEM & 0x01;
}

void init_random() {
	uint16_t seqNo = 0;
	for (int i = 0; i < 16; i++) {
		seqNo |= getRandomBit() << i;
	}

	srand(seqNo);
}

uint16_t net_get_time(void) {
	return timeValue;
}

void net_init_low(void) {
}

void net430_init(const uint8_t *mac_addr) {
	cpu_init();
	init_random();

	/* Select low-frequency mode */
	BCSCTL1 &= ~XTS;
	/* Set ACLK divider to 1 */
	BCSCTL1 |= DIVA_0;

	/* Select VLOCLK */
	BCSCTL3 &= ~(LFXT1S0 | LFXT1S1);
	BCSCTL3 |= LFXT1S_2;

	/* Initialize timer A0 */
	TA0CCTL0 = CM_0 | CCIE;
	TA0CTL = TASSEL_1 | ID_3 | MC_1 | TACLR;
	TA0CCR0 = (1500 * TIME_STEP);

#ifdef UART_ENABLE
	uart_init();
#endif
	delayMs(1500);

	P2DIR &= ~BIT1;
	P2REN |= BIT1;
	P2OUT |= BIT1;
	P2IES |= BIT1;
	P2IFG = 0;
	P2IE |= BIT1;

	__bis_SR_register(GIE);

	spi_init();

	/* Initialize RFM-module */
	//rf12_initialize(3, RF12_433MHZ, 33);

	spi_mem_init();

	enc_init(mac_addr);
	net_init(mac_addr);

#ifdef UDP_LOG
	logger_udp_init();
#endif
}

void net430_tick(void) {
    net_tick();
    if (!enc_idle) {
      enc_action();
    }
}

void __attribute__((interrupt TIMER0_A0_VECTOR))
TIMER0_A0_ISR(void) {
	__bic_SR_register_on_exit(CPUOFF);
	timeValue += TIME_STEP;
}
