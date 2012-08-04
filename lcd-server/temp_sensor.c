/*
 * temp_sensor.c
 *
 *  Created on: Aug 17, 2011
 *      Author: pf
 */

#include "temp_sensor.h"
#include <msp430.h>
#include <stdbool.h>
#include "cpu.h"

void __attribute__((interrupt(ADC10_VECTOR))) ADC10_ISR(void);

volatile bool temp_sensor_result_ready;

void
temp_sensor_init(void) {
	ADC10CTL0 = SREF_1 | ADC10SHT_3 | REFON | ADC10IE | ADC10SR | ADC10ON;
	ADC10CTL1 = ADC10DIV_3;
	ADC10AE0 = 0;

	temp_sensor_result_ready = false;
}

bool
temp_sensor_read_result(unsigned int *res) {
	if( temp_sensor_result_ready == true) {
		temp_sensor_result_ready = false;
		*res = ADC10MEM;
		return true;
	}
	return false;
}

void
temp_sensor_read(unsigned int channel) {
	if( channel < INCH_8) {
		ADC10AE0 = 1 << ((channel & 0xF000) >> 12);
	} else {
		ADC10AE0 = 0;
	}

	ADC10CTL1 &= ~INCH_15;
	ADC10CTL1 |= channel;

	ADC10CTL0 |= ENC | ADC10SC;
}

void __attribute__((interrupt(ADC10_VECTOR)))
ADC10_ISR(void) {
	ADC10CTL0 &= ~(ENC);
	temp_sensor_result_ready = true;
	__bic_SR_register_on_exit(CPUOFF);
}
