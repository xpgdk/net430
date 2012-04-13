/*
 * spi.h
 *
 */

#ifndef SPI_H_
#define SPI_H_

#include <stdint.h>

void spi_init(void);
uint8_t spi_send(uint8_t b);

#endif /* SPI_H_ */
