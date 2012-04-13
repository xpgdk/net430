#include <msp430.h>
#include "spi_mem.h"
#include "spi.h"

void spi_mem_init(void) {
	P2DIR |= MEM_CS;
	P2OUT |= MEM_CS;

	/* Configure sequential mode */
	SELECT_MEM();
	spi_send(0x1);
	spi_send(0x40);
	DESELECT_MEM();
}

void spi_mem_write(uint16_t addr, const uint8_t *buf, uint16_t count) {
	SELECT_MEM();
	spi_send(0x02);
	spi_send(addr >> 8);
	spi_send(addr & 0xFF);
	for(;count>0;count--) {
		spi_send(*buf);
		buf++;
	}
	DESELECT_MEM();
}

void spi_mem_read(uint16_t addr, uint8_t *buf, uint16_t count) {
	SELECT_MEM();
	spi_send(0x03);
	spi_send(addr >> 8);
	spi_send(addr & 0xFF);
	for(;count>0;count--) {
		*buf = spi_send(0xFF);
		buf++;
	}
	DESELECT_MEM();
}

void spi_mem_zero(uint16_t addr, uint16_t count) {
	SELECT_MEM();
	spi_send(0x02);
	spi_send(addr >> 8);
	spi_send(addr & 0xFF);
	for(;count>0;count--) {
		spi_send(0x00);
	}
	DESELECT_MEM();
}
