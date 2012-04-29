#include "udp.h"
#include "stack.h"

void handle_udp(uint8_t *macSource, uint8_t *sourceAddr, uint8_t *destIPAddr,
		uint16_t length, DATA_CB dataCb, void *priv) {

}

void net_udp_send(struct udp_packet_header *hdr, const uint8_t *data, uint16_t count) {
	//hdr->ipv6.payload_length = count + 8;
	hdr->ipv6.protocol = PROTO_UDP;
	net_start_ipv6_packet(&hdr->ipv6);

	uint8_t buf[2];

	buf[0] = hdr->sourcePort >> 8;
	buf[1] = hdr->sourcePort & 0xFF;
	net_send_data(buf, 2);
	calc_checksum(buf, 2);

	buf[0] = hdr->destPort >> 8;
	buf[1] = hdr->destPort & 0xFF;
	net_send_data(buf, 2);
	calc_checksum(buf, 2);

	buf[0] = (count+8) >> 8;
	buf[1] = (count+8) & 0xFF;
	net_send_data(buf, 2);
	calc_checksum(buf, 2);

	calc_checksum(data, count);

	net_send_dummy_checksum();
/*	checksum = ~checksum;
	buf[0] = checksum >> 8;
	buf[1] = checksum & 0xFF;
	net_send_data(buf, 2);*/
	net_send_data(data, count);

	net_end_ipv6_packet();
}
