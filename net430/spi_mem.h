/*
 * spi_mem.h
 *
 *  Created on: Apr 12, 2012
 *      Author: pf
 */

#ifndef SPI_MEM_H_
#define SPI_MEM_H_

#include <stdint.h>

#define MEM_CS	BIT0

#define SELECT_MEM()	P2OUT &= ~BIT0
#define DESELECT_MEM()	P2OUT |= BIT0

void spi_mem_init(void);
void spi_mem_write(uint16_t addr, const uint8_t *buf, uint16_t count);
void spi_mem_read(uint16_t addr, uint8_t *buf, uint16_t count);
void spi_mem_zero(uint16_t addr, uint16_t count);

#endif /* SPI_MEM_H_ */
