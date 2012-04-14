#ifndef ICMP_H_
#define ICMP_H_

#include "stack.h"

void handle_icmp(uint8_t *macSource, uint8_t *sourceAddr, uint8_t *destIPAddr, uint16_t length, DATA_CB dataCb, void *priv);
void net_send_icmp(uint8_t type, uint8_t code, uint8_t *body,
		uint16_t body_length);
void net_send_echo_reply(uint16_t id, uint16_t seqNo);

void send_neighbor_solicitation(const uint8_t *dst_mac, const uint8_t *src_addr,
		const uint8_t *dst_addr, const uint8_t *addr);
void send_neighbor_advertisment(const uint8_t *dst_mac, const uint8_t *src_addr,
		const uint8_t *dst_addr, const uint8_t *addr);
void send_router_solicitation(const uint8_t *src_addr, const uint8_t *dst_addr);
#endif
