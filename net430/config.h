/*
 * config.h
 *
 *  Created on: Apr 22, 2012
 *      Author: pf
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#define CPU_FREQ 	8
#define SPI_SPEED 2000000 // 2MHz

/* Duration of a single CPU cycle */
#define FCPU (CPU_FREQ*1000000)
#define CYCLE_DURATION (1000000000 / FCPU) /* nanoseconds */
#define SPI_DIV (FCPU/SPI_SPEED)

#endif /* CONFIG_H_ */
