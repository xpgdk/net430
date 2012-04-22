/*
 * config.h
 *
 *  Created on: Apr 22, 2012
 *      Author: pf
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#define CPU_FREQ 	8

/* Duration of a single CPU cycle */
#define FCPU (CPU_FREQ*1000000)
#define CYCLE_DURATION (1000000000 / FCPU) /* nanoseconds */

#endif /* CONFIG_H_ */
