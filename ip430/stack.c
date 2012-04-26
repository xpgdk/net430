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

#define	ROUTING_TABLE_FLAG_USED		(1<<0)

struct routing_table_entry {
	uint8_t prefix[16];
	uint8_t prefixLength;
	uint8_t flags;
	uint8_t nextHopMac[6];
};

/* State variables */
uint16_t checksum;
const uint8_t *enc_mac_addr;
//uint16_t eui64_id;
uint8_t net_state;

static bool doLookup;

/* We store three addresses in the address store (42 bytes)*/
//uint16_t address_store;
static uint8_t const *address_lookup = NULL;
static int16_t lookup_id;
static uint16_t net_store_id;
//static uint16_t lookup_addr_id;
static bool checksum_leftover_set = false;
static uint16_t checksum_leftover;

#define ADDR_MAP_COUNT	10
#define ADDR_MAP_SIZE 	(ADDR_MAP_COUNT*sizeof(struct addr_map_entry))
//static uint16_t addr_map_id;
static uint16_t addr_map_next = 0;

#define ROUTING_TABLE_COUNT 10
#define ROUTING_TABLE_SIZE	(ROUTING_TABLE_COUNT*sizeof(struct routing_table_entry))
//static uint16_t routing_table;

#define NET_STORE_SIZE (ADDR_MAP_SIZE + ADDRESS_STORE_SIZE + ROUTING_TABLE_SIZE + 8 + 16)
#define ADDR_MAP_OFFSET			0
#define ADDR_STORE_OFFSET 		(ADDR_MAP_OFFSET + ADDR_MAP_SIZE)
#define ROUTING_TABLE_OFFSET	(ADDR_STORE_OFFSET + ADDRESS_STORE_SIZE)
#define EUI_OFFSET				(ROUTING_TABLE_OFFSET + ROUTING_TABLE_SIZE)
#define LOOKUP_OFFSET			(EUI_OFFSET + 8)

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

void net_get_address(uint8_t offset, uint8_t *target) {
	CHECK_SP("net_get_addr: ");
	mem_read(net_store_id, ADDR_STORE_OFFSET + offset, target, 16);
}

void net_set_address(uint8_t offset, uint8_t *source) {
	CHECK_SP("net_set_addr: ");
	mem_write(net_store_id, ADDR_STORE_OFFSET + offset, source, 16);
}

bool routing_table_lookup(const uint8_t *destAddr, uint8_t *nextHopMac) {
	struct routing_table_entry entry;
	bool found = false;
	uint8_t prefixLength = 0;

	CHECK_SP("routing_table_lookup: ");

#if 0
	debug_puts("routing_table_lookup: ");
	print_addr(destAddr);
	debug_nl();
	debug_puts("mem ID: ");
	debug_puthex(net_store_id + ROUTING_TABLE_OFFSET);
	debug_nl();
#endif
	for (int i = 0; i < ROUTING_TABLE_COUNT; i++) {
		mem_read(net_store_id,
				ROUTING_TABLE_OFFSET + (i * sizeof(struct routing_table_entry)),
				&entry, sizeof(struct routing_table_entry));
#if 0
		debug_puts("Testing: ");
		print_addr(entry.prefix);
		debug_puts("/");
		debug_puthex(entry.prefixLength);
		debug_puts(" -> ");
		print_buf(entry.nextHopMac, 6);
		debug_nl();
#endif
		if (entry.flags == 0) {
			break;
		}

		if (memcmp(destAddr, entry.prefix, entry.prefixLength) == 0
				&& entry.prefixLength >= prefixLength) {
			memcpy(nextHopMac, entry.nextHopMac, 6);
#if 0
			debug_puts(" Match");
			debug_nl();
#endif
			found = true;
		}
		debug_nl();
	}

	return found;
}

bool routing_table_add(const uint8_t *prefix, uint8_t prefixLength,
		const uint8_t *nextHopMac) {
	struct routing_table_entry entry;

	CHECK_SP("routing_table_add: ");

	for (int i = 0; i < ROUTING_TABLE_COUNT; i++) {
		mem_read(net_store_id,
				ROUTING_TABLE_OFFSET + (i * sizeof(struct routing_table_entry)),
				&entry, sizeof(struct routing_table_entry));
#if 0
		debug_puts("Flags: ");
		debug_puthex(entry.flags);
		debug_nl();
#endif
		if (entry.flags == 0) {
#if 0
			debug_puts("Added entry to routing table: ");
			print_addr(prefix);
			debug_puts("/");
			debug_puthex(prefixLength);
			debug_puts(" -> ");
			print_buf(nextHopMac, 6);
			debug_nl();
#endif
			memcpy(entry.prefix, prefix, 16);
			memcpy(entry.nextHopMac, nextHopMac, 6);
			entry.prefixLength = prefixLength;
			entry.flags = ROUTING_TABLE_FLAG_USED;
			mem_write(
					net_store_id,
					ROUTING_TABLE_OFFSET
							+ (i * sizeof(struct routing_table_entry)), &entry,
					sizeof(struct routing_table_entry));
			return true;
		}
	}
	debug_puts("Routing table full");
	debug_nl();
	return false;
}

void assign_address_from_prefix(uint8_t *addr, uint8_t prefixLength) {
	if (prefixLength != 64) {
		debug_puts("Unsupported prefix length for Ethernet\n");
		return;
	}

	uint8_t eui64[8];

	mem_read(net_store_id, EUI_OFFSET, eui64, 8);

	uint8_t ipv6_addr[16];

	CHECK_SP("assign_address_from_prefix: ");

	memcpy(ipv6_addr, addr, prefixLength / 8);
	memcpy(ipv6_addr + prefixLength / 8, eui64, 8);
	debug_puts("IPv6 Address configured: ");
	print_addr(ipv6_addr);
	debug_nl();
	net_set_address(ADDRESS_STORE_MAIN_OFFSET, ipv6_addr);
}

void register_mac_addr(const uint8_t *mac, const uint8_t *addr) {
	if (has_ipv6_addr(addr)) {
		return;
	}
	//mem_read(addr_map_id, addt_map_next*sizeof(struct addr_map_entry), &e, count);
	mem_write(net_store_id,
			ADDR_MAP_OFFSET + (addr_map_next * sizeof(struct addr_map_entry)),
			mac, 6);
	mem_write(
			net_store_id,
			ADDR_MAP_OFFSET + (addr_map_next * sizeof(struct addr_map_entry))
					+ 6, addr, 16);
	/*memcpy(addr_map[addr_map_next].mac, mac, 6);
	 memcpy(addr_map[addr_map_next].addr, addr, 16);*/

	addr_map_next = (addr_map_next + 1) % ADDR_MAP_COUNT;

	debug_puts("Stored address in cache:");
	print_addr(addr);
	debug_puts(" -> ");
	print_buf(mac, 6);
	debug_nl();

	uint8_t buf[16];

	CHECK_SP("register_mac_addr: ");

	mem_read(net_store_id, LOOKUP_OFFSET, buf, 16);

	if (buf[0] != 0x0) {
		if (memcmp(buf, addr, 16) == 0) {
			net_send_deferred(lookup_id, mac);
			buf[0] = 0x00;
			mem_write(net_store_id, LOOKUP_OFFSET, buf, 16);
		}
	}
}

bool find_mac_addr(uint8_t *mac, const uint8_t *addr) {
	uint8_t addr_map[16];

	CHECK_SP("find_mac_addr: ");
	for (int i = 0; i < ADDR_MAP_COUNT; i++) {
		mem_read(net_store_id,
				ADDR_MAP_OFFSET + (i * sizeof(struct addr_map_entry)) + 6,
				addr_map, 16);
		if (memcmp(addr, addr_map, 16) == 0) {
			mem_read(net_store_id,
					ADDR_MAP_OFFSET + (i * sizeof(struct addr_map_entry)), mac,
					6);
			return true;
		}
	}
	return false;
}

bool has_ipv6_addr(const uint8_t *ipaddr) {
	uint8_t addr_map[16];
	CHECK_SP("has_ipv6_addr: ");
	for (int i = 0; i < ADDR_MAP_COUNT; i++) {
		mem_read(net_store_id,
				ADDR_MAP_OFFSET + (i * sizeof(struct addr_map_entry)) + 6,
				addr_map, 16);
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
	doLookup = false;
	debug_puts("MEM FREE:");
	debug_puthex(mem_free());
	debug_puts("\r\n");

#ifdef HAVE_TCP
	tcp_init();
#endif
	net_store_id = mem_alloc(NET_STORE_SIZE);
#if 0
	addr_map_id = mem_alloc(sizeof(struct addr_map_entry) * ADDR_MAP_COUNT);

	eui64_id = mem_alloc(8);
	lookup_addr_id = mem_alloc(16);
	address_store = mem_alloc(ADDRESS_STORE_SIZE);

	routing_table = mem_alloc(ROUTING_TABLE_SIZE);
#endif
	debug_puts("MEM FREE:");
	debug_puthex(mem_free());
	debug_puts("\r\n");
	//memcpy(mac_addr, mac, 6);
	enc_mac_addr = mac;
	debug_puts("MAC: ");
	print_buf(enc_mac_addr, 6);

	/* Set local/universal bit to 'local' */
	uint8_t eui64[8];
	eui64[0] = enc_mac_addr[0] & ~(1 << 1);
	eui64[1] = enc_mac_addr[1];
	eui64[2] = enc_mac_addr[2];
	eui64[3] = 0xFF;
	eui64[4] = 0xFE;
	eui64[5] = enc_mac_addr[3];
	eui64[6] = enc_mac_addr[4];
	eui64[7] = enc_mac_addr[5];

	mem_write(net_store_id, EUI_OFFSET, eui64, 8);

	debug_puts("EUI-64: ");
	print_buf(eui64, 8);

	uint8_t addr[16];
	uint8_t solicit_addr[16];
	addr[0] = 0xFE;
	addr[1] = 0x80;
	memset(addr + 2, 0x00, 6);
	memcpy(addr + 8, eui64, 8);

	print_addr(addr);
	debug_nl();
	net_set_address(ADDRESS_STORE_LINK_LOCAL_OFFSET, addr);

	memcpy(solicit_addr, solicited_mcast_prefix, 13);
	memcpy(solicit_addr + 13, addr + 13, 3);

	print_addr(addr);
	debug_nl();
	net_set_address(ADDRESS_STORE_SOLICITED_OFFSET, solicit_addr);

	send_neighbor_solicitation(ether_bcast, unspec_addr, solicit_addr, addr);

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

	uint8_t buf[4];

	checksum = /*arg->payload_length +*/ arg->protocol;
	checksum_leftover_set = false;
#ifdef DEBUG_CHECKSUM
	debug_puts("Checksum reset");
	debug_nl();
#endif

	struct etherheader header;

	memcpy(header.mac_source, enc_mac_addr, 6);

	address_lookup = NULL;

	if (is_null_mac(arg->dst_mac_addr)) {
		if (!routing_table_lookup(arg->dst_ipv6_addr, header.mac_dest)) {
			debug_puts("We are in trouble...");
			debug_nl();
		}

		if (is_null_mac(header.mac_dest)) {
			/* If we got no link-level destination, we need to do something...
			 */

			if (!find_mac_addr(header.mac_dest, arg->dst_ipv6_addr)) {
				/* If that fails, send a neighbor solicitation. But we need to store
				 the packet in secondary memory instead of transmitting it, until we have
				 the destination link-level address.
				 net_send_start() will deal with that as long as we use an all zero dst_mac_addr.
				 */
				address_lookup = arg->dst_ipv6_addr;
				debug_puts("MAC not found");
				debug_nl();
				memcpy(header.mac_dest, null_mac, 6);
			}
		}
	} else {
		memcpy(header.mac_dest, arg->dst_mac_addr, 6);
	}

	header.type[0] = (TYPE_IPV6 >> 8) & 0xFF;
	header.type[1] = TYPE_IPV6 & 0xFF;

	int16_t r = net_send_start(&header);
	if (r > 0) {
		debug_puts("Lookup ID set");
		debug_nl();
		lookup_id = r;
	}

	CHECK_SP("net_start_ipv6_packet: ");

	/* Version=6, traffic class=0, and flow label=0 part of the header */
	net_send_data(ipv6_header, 4);

	buf[0] = /*(arg->payload_length >> 8) & 0xFF*/ 0x00;
	buf[1] = /*arg->payload_length & 0xFF*/ 0x00;
	buf[2] = arg->protocol;
	buf[3] = 255;
	net_send_data(buf, 4);

	net_send_data(arg->src_ipv6_addr, 16);
	calc_checksum(arg->src_ipv6_addr, 16);

	net_send_data(arg->dst_ipv6_addr, 16);
	calc_checksum(arg->dst_ipv6_addr, 16);
}

void net_end_ipv6_packet() {
	uint16_t length = net_get_length()-(SIZE_IPV6_HEADER+SIZE_ETHERNET_HEADER);
	uint8_t buf[2];

	CHECK_SP("net_end_ipv6_packet: ");

	buf[0] = (length >> 8) & 0xFF;
	buf[1] = length & 0xFF;
	calc_checksum(buf, 2);
	net_send_replace_checksum(~checksum);
	net_send_at_offset(SIZE_ETHERNET_HEADER+4, length);
	net_send_end();

	if (address_lookup != NULL) {
		mem_write(net_store_id, LOOKUP_OFFSET, address_lookup, 16);
		doLookup = true;
#if 0
		/* Perform neighbor solicitation */
		debug_puts("Lookup of ");
		print_addr(address_lookup);
		debug_nl();
		uint8_t addr[16];
		net_get_address(ADDRESS_STORE_LINK_LOCAL_OFFSET, addr);
		send_neighbor_solicitation(ether_bcast, addr, address_lookup,
				address_lookup);
#endif
		net_state = STATE_WAITING_ADVERTISMENT;
	}
}

void net_tick(void) {
	CHECK_SP("net_tick, start: ");

#ifdef HAVE_TCP
	tcp_initialSeqNo++;
#endif

	switch (net_state) {
	case STATE_DAD: {
		uint8_t addr_link[16];
		CHECK_SP("net_tick, STATE_DAD: ");
		net_get_address(ADDRESS_STORE_LINK_LOCAL_OFFSET, addr_link);
		net_state = STATE_IDLE;
		debug_puts("IPv6 Link Local address: ");
		print_addr(addr_link);
		debug_nl();
		send_router_solicitation(addr_link, all_router_mcast);
		/* Ready to communicate */
	}
		break;
	case STATE_WAITING_ADVERTISMENT:
		if (doLookup) {
			doLookup = false;
			/* Perform neighbor solicitation */
			debug_puts("Lookup of ");
			print_addr(address_lookup);
			debug_nl();
			uint8_t addr[16];
			net_get_address(ADDRESS_STORE_LINK_LOCAL_OFFSET, addr);
			send_neighbor_solicitation(ether_bcast, addr, address_lookup,
					address_lookup);
		} else {
			net_drop_deferred(lookup_id);
			net_state = STATE_IDLE;
		}
		break;
	default:
		break;
	}
}

void calc_checksum(const uint8_t *buf, uint16_t count) {
	const uint8_t *data_ptr;
	const uint8_t *last_byte;
	uint16_t t;

	if( checksum_leftover_set && count > 0 ) {
		checksum_leftover_set = false;
#ifdef DEBUG_CHECKSUM
		debug_puts("Leftover of ");
		debug_puthex(checksum_leftover);
		debug_nl();
#endif
		/* An uneven number of bytes was calculated last, compensate for this */
		t = checksum_leftover + buf[0];
		checksum += t;
		if (t > checksum)
			checksum++;

		count--;
		buf++;
	}

#ifdef DEBUG_CHECKSUM
	debug_puts("Checksum of ");
	debug_puthex(count);
	debug_puts(" bytes");
	debug_nl();
#endif

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
#ifdef DEBUG_CHECKSUM
		debug_puts("Leftover set");
		debug_nl();
#endif
		checksum_leftover_set = true;
		checksum_leftover = data_ptr[0] << 8;
		/*t = (data_ptr[0] << 8);
		checksum += t;
		if (t > checksum)
			checksum++;*/
	}
}

void handle_ethernet(struct etherheader *header, uint16_t length,
		DATA_CB dataCb, void *priv) {
	uint16_t type = header->type[0] << 8;
	type |= header->type[1] & 0xFF;

	CHECK_SP("handle_ethernet: ");

	if (type == TYPE_IPV6) {
		handle_ipv6(header->mac_source, length, dataCb, priv);
	}
}

void handle_ipv6(uint8_t *macSource, uint16_t length, DATA_CB dataCb,
		void *priv) {
	uint16_t count;
	uint8_t buf[2];

	CHECK_SP("handle_ipv6, entry: ");

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

#ifdef DEBUG_IPV6
	debug_puts("IPv6 Addr of incoming packet: ");
	print_addr(destAddr);
	debug_nl();
#endif

	uint8_t addr[16];

	CHECK_SP("handle_ipv6, before check addr: ");

	net_get_address(ADDRESS_STORE_MAIN_OFFSET, addr);

	/* TODO: Follow header chain until we find something valid */

	bool receive = false;
	uint8_t *destination = NULL;

	if (memcmp(destAddr, addr, 16) == 0) {
		receive = true;
		destination = addr;
	}

	if (destination == NULL) {
		net_get_address(ADDRESS_STORE_LINK_LOCAL_OFFSET, addr);
		if (memcmp(destAddr, addr, 16) == 0) {
			receive = true;
			destination = addr;
		}
	}

	if (destination == NULL) {
		net_get_address(ADDRESS_STORE_SOLICITED_OFFSET, addr);
		if (memcmp(destAddr, addr, 16) == 0) {
			receive = true;
			destination = addr;
		}
	}

	if (destAddr[0] == 0xFF && destAddr[1] == 0x02 && destAddr[15] == 0x1) {
		receive = true;
	}

	if (!receive) {
#ifdef DEBUG_IPV6
		debug_puts("Not for us");
		debug_nl();
#endif
		return;
	}

#ifdef DEBUG_IPV6
	debug_puts("Receive. nextHeader: ");
	debug_puthex(nextHeader);
	debug_nl();

	PRINT_SP("Before protocol dispatch: ");
#endif

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
}

void print_addr(const uint8_t *addr) {
	for (int i = 0; i < 16; i += 2) {
		uint16_t a = (addr[i] << 8) | addr[i + 1];
		debug_puthex(a);
		if (i < 14)
			debug_puts(":");
	}
}

