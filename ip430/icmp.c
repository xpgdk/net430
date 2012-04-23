#include "icmp.h"
#include "stack.h"
#include "debug.h"
#include "mem.h"

#include <string.h>

void handle_icmp(uint8_t *macSource, uint8_t *sourceAddr, uint8_t *destIPAddr,
		uint16_t length, DATA_CB dataCb, void *priv) {
	uint8_t payload[length - 4];
	uint8_t type;

	dataCb(payload, 4, priv);

	type = payload[0];

	calc_checksum(payload, 4);

	uint16_t r = dataCb(payload, length - 4, priv);

	calc_checksum(payload, length - 4);


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
			uint8_t addr[16];
			net_get_address(ADDRESS_STORE_LINK_LOCAL_OFFSET, addr);
			if (memcmp(payload + 4, addr, 16) == 0) {
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
			//arg.payload_length = SIZE_ICMP_HEADER + length;
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
		uint8_t *c = payload + 12;
		while (c < payload + length - 4) {
			if (c[0] == 3) {
				uint8_t prefixLength = c[2];
				/* Prefix starts at offset 16 */
				print_addr(c + 16);
				uint8_t buf[16];
				net_get_address(ADDRESS_STORE_MAIN_OFFSET, buf);
				if (buf[0] == 0x00) {
					// null_mac as destination means link-local (go figure)
					routing_table_add(c+ 16, prefixLength/8, null_mac);

					// Default route
					routing_table_add(unspec_addr, 0, macSource);
					assign_address_from_prefix(c + 16, prefixLength);
					//mem_write(default_route_mac_id, 0, macSource, 6);
				} else {

				}
			}
			c += c[1] * 8;
		}
	}
		break;
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

	uint8_t buf[2];
	buf[0] = type;
	buf[1] = code;
	net_send_data(buf, 2);
	calc_checksum(buf, 2);

	net_send_dummy_checksum();

	net_send_data(body, body_length);
	calc_checksum(body, body_length);
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
	//arg.payload_length = payload_length + SIZE_ICMP_HEADER;
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
	//uint16_t payload_length = 20 + 8; /* Advertisment + target-link layer option*/
	uint8_t buf[20 + 8];

	struct ipv6_packet_arg arg;

	arg.dst_mac_addr = dst_mac;
	arg.dst_ipv6_addr = dst_addr;
	arg.src_ipv6_addr = src_addr;
	//arg.payload_length = payload_length + SIZE_ICMP_HEADER;
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
	//arg.payload_length = payload_length + SIZE_ICMP_HEADER;
	arg.protocol = PROTO_ICMP;

	net_start_ipv6_packet(&arg);
	buf[0] = buf[1] = buf[2] = buf[3] = 0x00;
	net_send_icmp(ICMP_TYPE_ROUTER_SOLICITATION, 0x00, buf, payload_length);
	net_end_ipv6_packet();
}
