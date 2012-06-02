/*
 * temp_sensor.h
 *
 *  Created on: Aug 17, 2011
 *      Author: pf
 */

#ifndef TEMP_SENSOR_H_
#define TEMP_SENSOR_H_

#include <stdbool.h>

void temp_sensor_init(void);
bool temp_sensor_read_result(unsigned int *res);
void temp_sensor_read(unsigned int channel);

#endif /* TEMP_SENSOR_H_ */
