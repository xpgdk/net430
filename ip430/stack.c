#include <stdio.h>
#include <string.h>
#include "stack.h"
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef HAVE_TCP
#include "tcp.h"
#endif

#include "icmp.h"
#include "udp.h"
#include "debug.h"
#include "mem.h"

struct addr_map_entry {
	uint8_t mac[6];
	uint8_t addr[16];
};

/* State variables */
uint16_t checksum;
uint8_t addr_solicited[16];
const uint8_t *enc_mac_addr;
uint8_t eui64[8];
uint8_t net_state;
uint8_t addr_link[16]; /* Link local is special */
uint8_t ipv6_addr[16]; /* TODO: Support multiple addresses */
uint16_t default_route_mac_id;

static uint8_t const *address_lookup = NULL;
static int16_t lookup_id;
static uint8_t lookup_addr[16];

#define ADDR_MAP_SIZE	10

static uint16_t addr_map_id;
static uint16_t addr_map_next = 0;

const uint8_t solicited_mcast_prefix[] = { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0x00 };
const uint8_t unspec_addr[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
const uint8_t all_router_mcast[] = { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };
const uint8_t ether_bcast[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
const uint8_t null_mac[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

/* First 4 bytes of the IPv6 header: version=6, traffic class=0, and flow label=0 */
static const uint8_t ipv6_header[] = { 0x60, 0x00, 0x00, 0x00 };

void construct_solicited_mcast_addr(uint8_t *solicited_mcast,
		const uint8_t *addr);

bool has_ipv6_addr(const uint8_t *ipaddr);

void assign_address_from_prefix(uint8_t *addr, uint8_t prefixLength) {
	if (prefixLength != 64) {
		debug_puts("Unsupported prefix length for Ethernet\n");
		return;
	}

	memcpy(ipv6_addr, addr, prefixLength / 8);
	memcpy(ipv6_addr + prefixLength / 8, eui64, 8);
	debug_puts("IPv6 Address configured: ");
	print_addr(ipv6_addr);
}

void register_mac_addr(const uint8_t *mac, const uint8_t *addr) {
	if (has_ipv6_addr(addr)) {
		return;
	}
	//mem_read(addr_map_id, addt_map_next*sizeof(struct addr_map_entry), &e, count);
	mem_write(addr_map_id, addr_map_next * sizeof(struct addr_map_entry), mac,
			6);
	mem_write(addr_map_id, addr_map_next * sizeof(struct addr_map_entry) + 6,
			addr, 16);
	/*memcpy(addr_map[addr_map_next].mac, mac, 6);
	 memcpy(addr_map[addr_map_next].addr, addr, 16);*/

	addr_map_next = (addr_map_next + 1) % ADDR_MAP_SIZE;

	debug_puts("Stored address in cache:");
	print_addr(addr);
	print_buf(mac, 6);

	if (lookup_addr[0] != 0x0) {
		if (memcmp(lookup_addr, addr, 16) == 0) {
			net_send_deferred(lookup_id, mac);
			lookup_addr[0] = 0x00;
		}
	}
}

bool find_mac_addr(uint8_t *mac, const uint8_t *addr) {
	for (int i = 0; i < ADDR_MAP_SIZE; i++) {
		uint8_t addr_map[16];
		mem_read(addr_map_id, i * sizeof(struct addr_map_entry) + 6, addr_map,
				16);
		if (memcmp(addr, addr_map, 16) == 0) {
			mem_read(addr_map_id, i * sizeof(struct addr_map_entry), mac, 6);
			return true;
		}
	}
	return false;
}

bool has_ipv6_addr(const uint8_t *ipaddr) {
	for (int i = 0; i < ADDR_MAP_SIZE; i++) {
		uint8_t addr_map[16];
		mem_read(addr_map_id, i * sizeof(struct addr_map_entry) + 6, addr_map,
				16);
		if (memcmp(ipaddr, addr_map, 16) == 0) {
			return true;
		}
	}
	return false;
}

bool is_mac_equal(const uint8_t *mac1, const uint8_t *mac2) {
	for (int i = 0; i < 6; i++) {
		if (mac1[i] != mac2[i]) {
			return false;
		}
	}
	return true;
}

bool is_null_mac(const uint8_t *mac) {
	for (int i = 0; i < 6; i++) {
		if (mac[i] != 0) {
			return false;
		}
	}
	return true;
}

void net_init(const uint8_t *mac) {
	debug_puts("MEM FREE:");
	debug_puthex(mem_free());
	debug_puts("\r\n");

#ifdef HAVE_TCP
	tcp_init();
#endif
	memset(ipv6_addr, 0x00, 16);
	addr_map_id = mem_alloc(sizeof(struct addr_map_entry) * ADDR_MAP_SIZE);

	default_route_mac_id = mem_alloc(16);

	debug_puts("MEM FREE:");
	debug_puthex(mem_free());
	debug_puts("\r\n");
	//memcpy(mac_addr, mac, 6);
	enc_mac_addr = mac;
	debug_puts("MAC: ");
	print_buf(enc_mac_addr, 6);

	/* Set local/universal bit to 'local' */
	eui64[0] = enc_mac_addr[0] & ~(1 << 1);
	eui64[1] = enc_mac_addr[1];
	eui64[2] = enc_mac_addr[2];
	eui64[3] = 0xFF;
	eui64[4] = 0xFE;
	eui64[5] = enc_mac_addr[3];
	eui64[6] = enc_mac_addr[4];
	eui64[7] = enc_mac_addr[5];

	debug_puts("EUI-64: ");
	print_buf(eui64, 8);

	addr_link[0] = 0xFE;
	addr_link[1] = 0x80;
	memset(addr_link + 2, 0x00, 6);
	memcpy(addr_link + 8, eui64, 8);

	print_addr(addr_link);

	memcpy(addr_solicited, solicited_mcast_prefix, 13);
	memcpy(addr_solicited + 13, addr_link + 13, 3);

	print_addr(addr_solicited);

	send_neighbor_solicitation(ether_bcast, unspec_addr, addr_solicited,
			addr_link);

	net_state = STATE_DAD;
}

void construct_solicited_mcast_addr(uint8_t *solicited_mcast,
		const uint8_t *addr) {
	memcpy(solicited_mcast, solicited_mcast_prefix, 13);
	memcpy(solicited_mcast + 13, addr + 13, 3);
}

void net_start_ipv6_packet(struct ipv6_packet_arg *arg) {
	/* IPv6 Header Format:

	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |Version| Traffic Class |           Flow Label                  |
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |         Payload Length        |  Next Header  |   Hop Limit   |
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |                                                               |
	 +                                                               +
	 |                                                               |
	 +                         Source Address                        +
	 |                                                               |
	 +                                                               +
	 |                                                               |
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |                                                               |
	 +                                                               +
	 |                                                               |
	 +                      Destination Address                      +
	 |                                                               |
	 +                                                               +
	 |                                                               |
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/

	/**
	 Checksum is calculated from the following pseudo header:
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |                                                               |
	 +                                                               +
	 |                                                               |
	 +                         Source Address                        +
	 |                                                               |
	 +                                                               +
	 |                                                               |
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |                                                               |
	 +                                                               +
	 |                                                               |
	 +                      Destination Address                      +
	 |                                                               |
	 +                                                               +
	 |                                                               |
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |                   Upper-Layer Packet Length                   |
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |                      zero                     |  Next Header  |
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	checksum = arg->payload_length + arg->protocol;

	struct etherheader header;

	memcpy(header.mac_source, enc_mac_addr, 6);

	if (is_null_mac(arg->dst_mac_addr)) {
		/* If we got no link-level destination, we need to consult the
		 cache...
		 */

		if (!find_mac_addr(header.mac_dest, arg->dst_ipv6_addr)) {
			/* If that fails, send a neighbor solicitation. But we need to store
			 the packet in secondary memory instead of transmitting it, until we have
			 the destination link-level address.
			 net_send_start() will deal with that as long as we use an all zero dst_mac_addr.
			 */
			address_lookup = arg->dst_ipv6_addr;
			debug_puts("MAC not found\n");
			memcpy(header.mac_dest, null_mac, 6);
		} else {
			address_lookup = NULL;
		}
	} else {
		address_lookup = NULL;
		memcpy(header.mac_dest, arg->dst_mac_addr, 6);
	}

	header.type[0] = (TYPE_IPV6 >> 8) & 0xFF;
	header.type[1] = TYPE_IPV6 & 0xFF;

	int16_t r = net_send_start(&header);
	if (r > 0) {
		debug_puts("Lookup ID set\n");
		lookup_id = r;
	}

	/* Version=6, traffic class=0, and flow label=0 part of the header */
	net_send_data(ipv6_header, 4);

	uint8_t buf[4];

	buf[0] = (arg->payload_length >> 8) & 0xFF;
	buf[1] = arg->payload_length & 0xFF;
	buf[2] = arg->protocol;
	buf[3] = 255;
	net_send_data(buf, 4);

	net_send_data(arg->src_ipv6_addr, 16);
	calc_checksum(arg->src_ipv6_addr, 16);

	net_send_data(arg->dst_ipv6_addr, 16);
	calc_checksum(arg->dst_ipv6_addr, 16);
}

void net_end_ipv6_packet() {
	net_send_end();

	if (address_lookup != NULL) {
		memcpy(lookup_addr, address_lookup, 16);
		/* Perform neighbor solicitation */
		debug_puts("Lookup of ");
		print_addr(lookup_addr);
		debug_puts("\r\n");
		send_neighbor_solicitation(ether_bcast, addr_link, address_lookup,
				address_lookup);
		net_state = STATE_WAITING_ADVERTISMENT;
	}
}

void net_tick(void) {
	switch (net_state) {
	case STATE_DAD:
		net_state = STATE_IDLE;
		debug_puts("IPv6 Link Local address: ");
		print_addr(addr_link);

		send_router_solicitation(addr_link, all_router_mcast);
		/* Ready to communicate */
		break;
	case STATE_WAITING_ADVERTISMENT:
		if (lookup_addr[0] != 0x0) {
			uint8_t mac[6];
			debug_puts("Sending to default\r\n");
			mem_read(default_route_mac_id, 0, mac, 6);
			print_buf(mac, 6);
			net_send_deferred(lookup_id, mac);
			debug_puts("Done\r\n");
			lookup_addr[0] = 0x00;
		} else {
			net_drop_deferred(lookup_id);
		}
		net_state = STATE_IDLE;
		break;
	default:
		break;
	}
}

void calc_checksum(const uint8_t *buf, uint16_t count) {
	const uint8_t *data_ptr;
	const uint8_t *last_byte;
	uint16_t t;

	data_ptr = buf;
	last_byte = data_ptr + count - 1;

	while (data_ptr < last_byte) {
		t = (data_ptr[0] << 8) + data_ptr[1];
		checksum += t;
		if (t > checksum)
			checksum++;
		data_ptr += 2;
	}
	if (data_ptr == last_byte) {
		t = (data_ptr[0] << 8);
		checksum += t;
		if (t > checksum)
			checksum++;
	}
}

void handle_ethernet(struct etherheader *header, uint16_t length,
		DATA_CB dataCb, void *priv) {
#if 0
	debug_puts("Dest: ");
	print_buf(header->mac_dest, 6);
	debug_puts("\r\n");
	debug_puts("Src : ");
	print_buf(header->mac_source, 6);
	debug_puts("\r\n");
	debug_puts("Ethernet Type: ");
	print_buf(header->type, 2);
	debug_puts(", ");
#endif
	uint16_t type = header->type[0] << 8;
	type |= header->type[1] & 0xFF;

	if (type == TYPE_IPV6) {
//		debug_puts("IPv6\n");
		handle_ipv6(header->mac_source, length, dataCb, priv);
	}
}

void handle_ipv6(uint8_t *macSource, uint16_t length, DATA_CB dataCb,
		void *priv) {
	uint16_t count;
	uint8_t buf[2];

	checksum = 0;

	count = dataCb(buf, 2, priv);
	if (count != 2) {
		debug_puts("Failed to read");
		return;
	}

	/* IPv6 version is 4 most significant bits */
	uint8_t version = (buf[0] >> 4) & 0xF;

	/* 4-lowest bit from buf[0] and 4-highest bits from buf[1]
	 * are the traffic class
	 */
	uint8_t traffic_class = (buf[0] & 0xF) << 4 | ((buf[1] >> 4) & 0xF);

	/* Read and ignore flow label */
	dataCb(buf, 2, priv);

	/* Read payload length */
	dataCb(buf, 2, priv);

	uint16_t payload_length = buf[0] << 8 | buf[1];

	uint8_t nextHeader;
	dataCb(&nextHeader, 1, priv);

	uint8_t hopLimit;
	dataCb(&hopLimit, 1, priv);

	uint8_t sourceAddr[16];
	dataCb(sourceAddr, 16, priv);

	uint8_t destAddr[16];
	dataCb(destAddr, 16, priv);

	checksum = nextHeader + payload_length;
	calc_checksum(sourceAddr, 16);
	calc_checksum(destAddr, 16);

	/* TODO: Follow header chain until we find something valid */

	bool receive = false;
	uint8_t *destination = NULL;
	/* Is this packet destined for us? */
	if (memcmp(destAddr, addr_link, 16) == 0) {
		receive = true;
		destination = addr_link;
	} else if (memcmp(destAddr, addr_solicited, 16) == 0) {
		receive = true;
		destination = addr_solicited;
	} else if (destAddr[0] == 0xFF && destAddr[1] == 0x02
			&& destAddr[15] == 0x1) {
		receive = true;
	} else if (memcmp(destAddr, ipv6_addr, 16) == 0) {
		receive = true;
		destination = ipv6_addr;
	}

	if (!receive) {
		return;
	}

	switch (nextHeader) {
	case PROTO_ICMP:
		handle_icmp(macSource, sourceAddr, destination, payload_length, dataCb,
				priv);
		break;
	case PROTO_UDP:
		handle_udp(macSource, sourceAddr, destination, payload_length, dataCb,
				priv);
		break;
#ifdef HAVE_TCP
	case PROTO_TCP:
		handle_tcp(macSource, sourceAddr, destination, payload_length, dataCb,
				priv);
		break;
#endif
	}
}

void print_buf(const uint8_t *data, unsigned int count) {
	for (unsigned int i = 0; i < count; i++) {
		debug_puthex(data[i]);
		debug_puts(":");
	}
	debug_nl();
}

void print_addr(const uint8_t *addr) {
	for (int i = 0; i < 16; i += 2) {
		uint16_t a = (addr[i] << 8) | addr[i + 1];
		debug_puthex(a);
		if (i < 14)
			debug_puts(":");
	}
	debug_nl();
}

