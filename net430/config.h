/*
 * config.h
 *
 *  Created on: Apr 22, 2012
 *      Author: pf
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#define CPU_FREQ 	8
#define SPI_SPEED 8000000 // 8MHz
#define RF12_SPI_SPEED 1000000 // 1MHz
#define UDP_LOG

#undef UART_LOG
#undef UART_ENABLE

/* Duration of a single CPU cycle */
#define FCPU (CPU_FREQ*1000000)
#define CYCLE_DURATION (1000000000 / FCPU) /* nanoseconds */
#define SPI_DIV (FCPU/SPI_SPEED)
#define RF12_SPI_DIV (FCPU/RF12_SPI_SPEED)

#endif /* CONFIG_H_ */
