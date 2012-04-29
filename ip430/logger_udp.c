/*
 * logger_udp.c
 *
 *  Created on: Apr 29, 2012
 *      Author: pf
 */

#include "config.h"
#if defined(UDP_LOG)

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "stack.h"
#include "udp.h"
#include "mem.h"

static struct udp_packet_header log_header;
#if 1
const static uint8_t log_dest[] = {0x20, 0x01, 0x16, 0xd8, 0xdd, 0xaa, 0x00, 0x1,
	0x02, 0x23, 0x54, 0xff, 0xfe, 0xd5, 0x46, 0xf0};
#else
const static uint8_t log_dest[] = {0x20,0x01, 0x16, 0xd8, 0xdd, 0xaa, 0x00, 0x02, 
	0x4c,0x5f, 0xe9,0xff, 0xfe,0x01, 0x1e, 0x59};
#endif
static uint8_t log_src_ip[16];
static int logger_mem;
static uint16_t logger_used;
static bool logger_sending;

const static uint8_t log_dest_mac[] = {0x00,0x23,0x54,0xd5,0x46,0xf0};
void
logger_udp_init(void) {
//	net_get_address(ADDRESS_STORE_MAIN_OFFSET, log_src_ip);
	log_header.ipv6.dst_mac_addr = log_dest_mac;
	log_header.ipv6.dst_ipv6_addr = log_dest;
	log_header.ipv6.src_ipv6_addr = log_src_ip;
	log_header.sourcePort = 2000;
	log_header.destPort = 5000;

	logger_mem = mem_alloc(1500);
	logger_used = 0;
	logger_sending = false;
}

void
logger_udp_transmit(void) {
	net_get_address(ADDRESS_STORE_MAIN_OFFSET, log_src_ip);
	uint8_t buf[10];
	uint16_t offset = 0;
	logger_sending = true;
	while( logger_used > 0) {
		uint16_t count = sizeof(buf);
		if( logger_used < count) {
			count = logger_used;
		}
		mem_read(logger_mem, offset, buf, count);
		net_udp_send(&log_header, buf, count);

		logger_used -= count;
		offset += count;
	}
	logger_sending = false;
}

void
debug_puts(const char *str) {
	if (logger_sending) 
		return;
	mem_write(logger_mem, logger_used, str, strlen(str));
	logger_used += strlen(str);
}

void
debug_puthex(uint16_t v) {
	char buf[10];
	//sprintf(buf, "%X", v);
	itoa(v, buf, 16);
	debug_puts(buf);
}

void
debug_nl() {
	debug_puts("\n");
}


#endif
