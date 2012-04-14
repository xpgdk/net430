#include <stdio.h>
#include <string.h>
#include "stack.h"
#include <stdbool.h>
#include <stdlib.h>

#ifdef HAVE_TCP
#include "tcp.h"
#endif

#include "udp.h"
#include "debug.h"
#include "mem.h"

//#define DEBUG
//#define DEBUG_ETHERNET
//#define DEBUG_IPV6
//#define DEBUG_ICMP

#ifdef DEBUG
#define DPRINTF(x)	printf x
#define DPRINTBUF(x)	print_buf x
#define DPRINTADDR(x)	print_addr x
#else
#define	DPRINTF(x)
#define DPRINTBUF(x)
#define DPRINTADDR
#endif

#ifdef DEBUG_ETHERNET
#define DPRINTF_ETHERNET(x)	printf x
#define DPRINTBUF_ETHERNET(x)	print_buf x
#define DPRINTADDR_ETHERNET(x)	print_addr x
#else
#define DPRINTF_ETHERNET(x)
#define DPRINTBUF_ETHERNET(x)
#define DPRINTADDR_ETHERNET(x)
#endif

#ifdef DEBUG_IPV6
#define DPRINTF_IPV6(x)	printf x
#define DPRINTBUF_IPV6(x)	print_buf x
#define DPRINTADDR_IPV6(x)	print_addr x
#else
#define DPRINTF_IPV6(x)
#define DPRINTBUF_IPV6(x)
#define DPRINTADDR_IPV6(x)
#endif

#ifdef DEBUG_ICMP
#define DPRINTF_ICMP(x)	printf x
#define DPRINTBUF_ICMP(x)	print_buf x
#else
#define DPRINTF_ICMP(x)
#define DPRINTBUF_ICMP(x)
#endif

struct addr_map_entry {
	uint8_t mac[6];
	uint8_t addr[16];
};

/* State variables */
uint16_t checksum;
uint8_t addr_solicited[16];
static const uint8_t *enc_mac_addr;
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

#define STATE_INIT			0
#define STATE_DAD			1
#define STATE_IDLE			2
#define STATE_WAITING_ADVERTISMENT	3
#define STATE_INVALID			4

static const uint8_t solicited_mcast_prefix[] = { 0xFF, 0x02, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0x00 };
static const uint8_t unspec_addr[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t all_router_mcast[] = { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };
const uint8_t ether_bcast[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
const uint8_t null_mac[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

/* First 4 bytes of the IPv6 header: version=6, traffic class=0, and flow label=0 */
static const uint8_t ipv6_header[] = { 0x60, 0x00, 0x00, 0x00 };

void send_neighbor_solicitation(const uint8_t *dst_mac, const uint8_t *src_addr,
		const uint8_t *dst_addr, const uint8_t *addr);
void send_neighbor_advertisment(const uint8_t *dst_mac, const uint8_t *src_addr,
		const uint8_t *dst_addr, const uint8_t *addr);
void send_router_solicitation(const uint8_t *src_addr, const uint8_t *dst_addr);
void construct_solicited_mcast_addr(uint8_t *solicited_mcast,
		const uint8_t *addr);
void assign_address_from_prefix(uint8_t *ipv6_addr, uint8_t prefixLength);

void net_send_icmp(uint8_t type, uint8_t code, uint8_t *body,
		uint16_t body_length);
void net_send_echo_reply(uint16_t id, uint16_t seqNo);
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
#ifdef HAVE_TCP
	tcp_init();
#endif
	memset(ipv6_addr, 0x00, 16);
	debug_puts("MEM FREE:");
	debug_puthex(mem_free());
	debug_puts("\r\n");
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

void net_send_icmp(uint8_t type, uint8_t code, uint8_t *body,
		uint16_t body_length) {
	/**
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |     Type      |     Code      |          Checksum             |
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |                                                               |
	 +                         Message Body                          +
	 |                                                               |
	 */

	calc_checksum(body, body_length);
	uint8_t buf[4];
	buf[0] = type;
	buf[1] = code;
	buf[2] = 0;
	buf[3] = 0;
	calc_checksum(buf, 4);

	checksum = ~checksum;
	buf[2] = (checksum >> 8) & 0XFF;
	buf[3] = checksum & 0xFF;
	net_send_data(buf, 4);

	net_send_data(body, body_length);
}

void send_neighbor_solicitation(const uint8_t *dst_mac, const uint8_t *src_addr,
		const uint8_t *dst_addr, const uint8_t *addr) {
	uint16_t payload_length = 20; /* Solicitation */
	uint8_t buf[20 + 8]; /* Room for solicitation + source link-layer option */

	if (src_addr != unspec_addr) {
		payload_length += 8;
	}

	struct ipv6_packet_arg arg;
	arg.dst_mac_addr = dst_mac;
	arg.dst_ipv6_addr = dst_addr;
	arg.src_ipv6_addr = src_addr;
	arg.payload_length = payload_length + SIZE_ICMP_HEADER;
	arg.protocol = PROTO_ICMP;

#if 1
	net_start_ipv6_packet(&arg);

	/* Reserved bits */
	buf[0] = buf[1] = buf[2] = buf[3] = 0x00;

	/* Address */
	memcpy(buf + 4, addr, 16);

	/* Option */
	if (src_addr != unspec_addr) {
		buf[20] = 0x01;
		buf[21] = 0x01;
		memcpy(buf + 22, enc_mac_addr, 6);
	}

	net_send_icmp(ICMP_TYPE_NEIGHBOR_SOLICITATION, 0x00, buf, payload_length);
	net_end_ipv6_packet();
#endif
}

void send_neighbor_advertisment(const uint8_t *dst_mac, const uint8_t *src_addr,
		const uint8_t *dst_addr, const uint8_t *addr) {
	/*
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |     Type      |     Code      |          Checksum             | ICMP
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |R|S|O|                     Reserved                            | BODY \/
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |                                                               |
	 +                                                               +
	 |                                                               |
	 +                       Target Address                          +
	 |                                                               |
	 +                                                               +
	 |                                                               |
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |   Options ...
	 +-+-+-+-+-+-+-+-+-+-+-+-
	 */
	/* Length here does not include ICMP header */
	uint16_t payload_length = 20 + 8; /* Advertisment + target-link layer option*/
	uint8_t buf[20 + 8];

	struct ipv6_packet_arg arg;

	arg.dst_mac_addr = dst_mac;
	arg.dst_ipv6_addr = dst_addr;
	arg.src_ipv6_addr = src_addr;
	arg.payload_length = payload_length + SIZE_ICMP_HEADER;
	arg.protocol = PROTO_ICMP;

	net_start_ipv6_packet(&arg);

	buf[0] = 0x60; /* Solicited + Override set */
	buf[1] = buf[2] = buf[3] = 0x00; /* Reserved */
	memcpy(buf + 4, addr, 16);
	buf[20] = 0x02;
	buf[21] = 0x01;
	memcpy(buf + 22, enc_mac_addr, 6);

	net_send_icmp(ICMP_TYPE_NEIGHBOR_ADVERTISMENT, 0x00, buf, sizeof(buf));

	net_end_ipv6_packet();
}

void send_router_solicitation(const uint8_t *src_addr, const uint8_t *dst_addr) {
	uint16_t payload_length = 4;
	uint8_t buf[payload_length];

	struct ipv6_packet_arg arg;
	arg.dst_mac_addr = ether_bcast;
	arg.dst_ipv6_addr = dst_addr;
	arg.src_ipv6_addr = src_addr;
	arg.payload_length = payload_length + SIZE_ICMP_HEADER;
	arg.protocol = PROTO_ICMP;

	net_start_ipv6_packet(&arg);
	buf[0] = buf[1] = buf[2] = buf[3] = 0x00;
	net_send_icmp(ICMP_TYPE_ROUTER_SOLICITATION, 0x00, buf, payload_length);
	net_end_ipv6_packet();
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
	DPRINTF_IPV6(("IP Version: %d\n", version));

	/* 4-lowest bit from buf[0] and 4-highest bits from buf[1]
	 * are the traffic class
	 */
	uint8_t traffic_class = (buf[0] & 0xF) << 4 | ((buf[1] >> 4) & 0xF);
	DPRINTF_IPV6(("Traffic class: %d\n", traffic_class));

	/* Read and ignore flow label */
	dataCb(buf, 2, priv);

	/* Read payload length */
	dataCb(buf, 2, priv);

	uint16_t payload_length = buf[0] << 8 | buf[1];
	DPRINTF_IPV6(("Payload length: %d\n", payload_length));

	uint8_t nextHeader;
	dataCb(&nextHeader, 1, priv);
	DPRINTF_IPV6(("Next Header: %d\n", nextHeader));

	uint8_t hopLimit;
	dataCb(&hopLimit, 1, priv);
	DPRINTF_IPV6(("Hop Limit: %d\n", hopLimit));

	uint8_t sourceAddr[16];
	dataCb(sourceAddr, 16, priv);

	uint8_t destAddr[16];
	dataCb(destAddr, 16, priv);

	checksum = nextHeader + payload_length;
	calc_checksum(sourceAddr, 16);
	calc_checksum(destAddr, 16);

	DPRINTADDR_IPV6((sourceAddr)); DPRINTADDR_IPV6((destAddr));

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
		handle_tcp(macSource, sourceAddr, destination, payload_length, dataCb, priv);
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

void handle_icmp(uint8_t *macSource, uint8_t *sourceAddr, uint8_t *destIPAddr,
		uint16_t length, DATA_CB dataCb, void *priv) {
	uint8_t payload[length - 4];
	uint8_t type;

	dataCb(payload, 4, priv);
	DPRINTF_ICMP(("Type: %d\n", payload[0]));
	debug_puts("ICMP\r\n");
	type = payload[0];
	DPRINTF_ICMP(("Code: %d\n", payload[1]));

	DPRINTF_ICMP(("Checksum: ")); DPRINTBUF_ICMP((payload+2, 2));
	calc_checksum(payload, 4);

	uint16_t r = dataCb(payload, length - 4, priv);
	DPRINTF_ICMP(("Expected: %d, got: %d\n", length-4, r));

	calc_checksum(payload, length - 4);

	DPRINTF_ICMP(("Calculated Checksum: %X\n", checksum));

	if (checksum != 0xFFFF) {
		//printf("Invalid checksum\n");
		return;
	}

	if (net_state != STATE_IDLE && type != ICMP_TYPE_NEIGHBOR_SOLICITATION
			&& type != ICMP_TYPE_NEIGHBOR_ADVERTISMENT)
		return;

	switch (type) {
	case ICMP_TYPE_NEIGHBOR_SOLICITATION:
		/* First 4 bytes are 'reserved', we ignore them.
		 Next 16 bytes are the target address
		 */
		//if( memcmp(payload+4, addr_link, 16) == 0) {
		/* This solicitation is for us, send an advertisment back */
		//printf("Got solicication for ");
		print_addr(payload + 4);

		if (length > 20) {
			//printf("Option present\n");
			if (payload[20] == 0x01) {
				/* We now got the link-layer address and IPv6 address of someone, store it */
				register_mac_addr(payload + 22, sourceAddr);
				//printf("Option is Source-Link\n");
				//printf("Source layer address: ");
				print_buf(payload + 22, 6);
				//send_neighbor_advertisment(payload+22, addr_link, sourceAddr, addr_link);
				send_neighbor_advertisment(payload + 22, payload + 4,
						sourceAddr, payload + 4);
			}
		}

		//}
		break;
	case ICMP_TYPE_NEIGHBOR_ADVERTISMENT:
		/* We ignore first 4 bytes */

		if (net_state == STATE_DAD) {
			if (memcmp(payload + 4, addr_link, 16) == 0) {
				//printf("Duplicate address detected\n");
				net_state = STATE_INVALID;
				return;
			}
		}

		register_mac_addr(macSource, payload + 4);
		net_state = STATE_IDLE;
		break;
	case ICMP_TYPE_ECHO_REQUEST:
		if (length >= 8) {
			uint16_t id = (payload[0] << 8) | payload[1];
			uint16_t seqNo = (payload[2] << 8) | payload[3];
			//printf("Echo request, id: %X, seqNo: %X\n", id, seqNo);
			struct ipv6_packet_arg arg;
			arg.dst_mac_addr = null_mac;
			arg.dst_ipv6_addr = sourceAddr;
			arg.src_ipv6_addr = destIPAddr;
			arg.payload_length = SIZE_ICMP_HEADER + length;
			arg.protocol = PROTO_ICMP;

			net_start_ipv6_packet(&arg);
			net_send_icmp(ICMP_TYPE_ECHO_REPLY, 0, payload, length);
			net_end_ipv6_packet();
		}
		break;
	case ICMP_TYPE_ROUTER_ADVERTISMENT:
		/* Ignore first 12 bytes, as we are only interested in
		 addresses. Next, loop through the options in the payload
		 */
	{

		debug_puts("Got router advertisment\n");
		uint8_t *c = payload + 12;
		while (c < payload + length - 4) {
			//printf("%p < %p\n, ", c, payload + length-4);
			//printf("Option %d, length: %d\n", c[0], c[1]);
			if (c[0] == 3) {
				uint8_t prefixLength = c[2];
				/* Prefix starts at offset 16 */
				//printf("Addr / %d: ", prefixLength);
				print_addr(c + 16);

				if (ipv6_addr[0] == 0x00) {
					assign_address_from_prefix(c + 16, prefixLength);
					mem_write(default_route_mac_id, 0, macSource, 16);
				} else {

				}
			}
			c += c[1] * 8;
		}
	}
		break;
	}
}
