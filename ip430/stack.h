#ifndef STACK_H
#define STACK_H

#include <stdint.h>

#undef DEBUG_IPV6
#undef DEBUG_ICMP
#undef DEBUG_TCP
#define DEBUG_CHECKSUM

struct etherheader {
	uint8_t mac_dest[6];
	uint8_t mac_source[6];
	uint8_t type[2];
};

struct etherframe {
	struct etherheader header;
	uint8_t payload[1500];
};

#define PTR_TYPE_UNUSED		0
#define PTR_TYPE_PRIMARY	1
#define PTR_TYPE_SECONDARY 	2
/* Pointer to an IPv6 address, which either resides
 * in main memory or secondary memory */
struct ipv6_addr_ptr {
	uint8_t		type;
	union {
		uint8_t *ptr;
		uint16_t mem_offset;
	} ref;
};

/* Arguments used when sending an IPv6 packet.
   This structure as a maximum references:
	6 + 16 + 16 + 2 + 1 = 41 bytes
 */
struct ipv6_packet_arg {
	const uint8_t 	*dst_mac_addr; /* May be NULL */
	const uint8_t 	*dst_ipv6_addr;
	const uint8_t 	*src_ipv6_addr; /* May be NULL */
//	uint16_t	payload_length;
	uint8_t		protocol;
};

extern const uint8_t	ether_bcast[];
extern const uint8_t	null_mac[];
extern const uint8_t	unspec_addr[];
extern uint16_t		checksum;

extern uint8_t		net_state;
extern const uint8_t *enc_mac_addr;

#define	ADDRESS_STORE_SIZE				(16*3)
#define	ADDRESS_STORE_LINK_LOCAL_OFFSET	(16*0)
#define ADDRESS_STORE_SOLICITED_OFFSET	(16*1)
#define	ADDRESS_STORE_MAIN_OFFSET		(16*2)

#define TYPE_IPV6 	0x86DD

#define PROTO_UDP	17 // 0x11
#define PROTO_TCP	6  // 0x06
#define PROTO_ICMP	58 // 0x3A

#define ICMP_TYPE_ROUTER_SOLICITATION	133 // 0x85
#define ICMP_TYPE_ROUTER_ADVERTISMENT	134 // 0x86
#define ICMP_TYPE_NEIGHBOR_SOLICITATION 135 // 0x87
#define ICMP_TYPE_NEIGHBOR_ADVERTISMENT 136 // 0x88
#define ICMP_TYPE_ECHO_REQUEST			128 // 0x89
#define ICMP_TYPE_ECHO_REPLY			129 // 0x8A

#define SIZE_ETHERNET_HEADER	sizeof(struct etherheader)
#define SIZE_IPV6_HEADER		40
#define SIZE_ICMP_HEADER		4
#define SIZE_TCP_HEADER			20

#define STATE_INIT			0
#define STATE_DAD			1
#define STATE_IDLE			2
#define STATE_WAITING_ADVERTISMENT	3
#define STATE_INVALID			4

#define CONV_16(b) ( ((*(b+0)) << 8) | (*(b+1)) )

static uint32_t CONV_32(uint8_t *buf) {
	uint32_t r = (uint32_t)buf[0] << 24;
	r |= (uint32_t)buf[1] << 16;
	r |= (uint32_t)buf[2] << 8;
	r |= (uint32_t)buf[3];

	return r;
}

static void CONV_OUT_32(uint8_t *buf, uint32_t i) {
	buf[0] = (i >> 24) & 0xFF;
	buf[1] = (i >> 16) & 0xFF;
	buf[2] = (i >> 8 ) & 0xFF;
	buf[3] = i & 0xFF;
}

static void CONV_OUT_16(uint8_t *buf, uint16_t i) {
	buf[0] = (i >> 8 ) & 0xFF;
	buf[1] = i & 0xFF;
}

typedef uint16_t(*DATA_CB)(uint8_t *buf, uint16_t count, void *priv);

void net_init(const uint8_t *mac);
void net_tick(void);
void net_get_address(uint8_t offset, uint8_t *target);
void net_set_address(uint8_t offset, uint8_t *source);

void handle_ethernet(struct etherheader *header, uint16_t length, DATA_CB dataCb, void *priv);
void handle_ipv6(uint8_t *macSource, uint16_t length, DATA_CB dataCb, void *priv);
void print_buf(const uint8_t *data, unsigned int count);
void print_addr(const uint8_t *addr);
void calc_checksum(const uint8_t *buf, uint16_t count);

/* Implemented by low-level driver */
int16_t net_send_start(struct etherheader *header);
void net_send_data(const uint8_t *buf, uint16_t count);
void net_send_end(void);
void net_send_deferred(int16_t id, uint8_t const *dstMac);
void net_drop_deferred(int16_t id);
void net_send_dummy_checksum(void);
void net_send_replace_checksum(uint16_t checksum);
void net_send_at_offset(uint16_t offset, uint16_t length);
uint16_t net_get_length(void);

/* Send IPv6 header and perform checksum calculation according to the
   pseudo header used by UDP, TCP, and ICMP */
void net_start_ipv6_packet(struct ipv6_packet_arg *arg);
void net_end_ipv6_packet();

void register_mac_addr(const uint8_t *mac, const uint8_t *addr);
void assign_address_from_prefix(uint8_t *ipv6_addr, uint8_t prefixLength);
#endif
