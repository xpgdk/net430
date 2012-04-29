/*
 * udp.h
 *
 *  Created on: Apr 13, 2012
 *      Author: pf
 */

#ifndef UDP_H_
#define UDP_H_

#include "stack.h"

struct udp_packet_header {
	struct ipv6_packet_arg ipv6;
	uint16_t sourcePort;
	uint16_t destPort;
};

void handle_udp(uint8_t *macSource, uint8_t *sourceAddr, uint8_t *destIPAddr,
		uint16_t length, DATA_CB dataCb, void *priv);

void net_udp_send(struct udp_packet_header *hdr, const uint8_t *data, uint16_t count);
//void net_start_udp_packet(struct ipv6_packet_arg *arg);
#endif /* UDP_H_ */
