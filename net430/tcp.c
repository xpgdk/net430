#ifdef HAVE_TCP
#include <stdint.h>
#include <string.h>

#include "tcp.h"
#include "stack.h"

#define TCP_STATE_NONE		0
#define TCP_STATE_LISTEN	1
#define TCP_STATE_SYN_SENT	2
#define TCP_STATE_SYN_RECEIVED 	3
#define TCP_STATE_ESTABLISHED	4

#define RECV_WINDOW		200

struct tcb {
	uint8_t	 local_addr[16];
	uint8_t  remote_addr[16];
	uint16_t tcp_local_port;
	uint16_t tcp_remote_port;

	uint32_t tcp_snd_una;
	uint32_t tcp_snd_nxt;
	uint32_t tcp_snd_wnd;
	uint32_t tcp_iss;

	uint32_t tcp_rcv_nxt;
	uint32_t tcp_rcv_wnd;
	uint32_t tcp_irs;
	uint8_t	tcp_state;
};

static struct tcb tcbs[1];
static uint16_t tcb_count;

/**
TODO: Add retransmission queue and a timer tick to retransmit packages
*/

void
tcp_send(struct tcb *tcb, uint16_t flags, const uint8_t *data, uint32_t count) {
	struct ipv6_packet_arg arg;
	uint8_t buf[20];

	arg.dst_mac_addr = null_mac;
	arg.dst_ipv6_addr = tcb->remote_addr;
	arg.src_ipv6_addr = tcb->local_addr;
	arg.payload_length = SIZE_TCP_HEADER + count;
	arg.protocol = PROTO_TCP;

	net_start_ipv6_packet(&arg);
	calc_checksum(data, count);

	buf[0] = (tcb->tcp_local_port >> 8) & 0xFF;
	buf[1] = tcb->tcp_local_port & 0xFF;
	buf[2] = (tcb->tcp_remote_port >> 8) & 0xFF;
	buf[3] = (tcb->tcp_remote_port & 0xFF);
	CONV_OUT_32(buf+4, tcb->tcp_snd_nxt);
	CONV_OUT_32(buf+8, tcb->tcp_rcv_nxt);
	print_buf(buf+8, 4);
	buf[12] = 0x05 << 4; // Data offset
	buf[13] = flags;
	CONV_OUT_16(buf+14, RECV_WINDOW);
	buf[16] = buf[17] = 0x00;
	buf[18] = buf[19] = 0x00;
	calc_checksum(buf, 20);
	CONV_OUT_16(buf+16, ~checksum);

	net_send_data(buf, 20);
	net_send_data(data, count);

	net_end_ipv6_packet();

	if( count > 0 ) {
		tcb->tcp_snd_nxt += count;
	} /*else if (flags & TCP_ACK) {
		tcb->tcp_snd_nxt++;
	}*/

	//printf("Next sequence number: %d\n", tcb->tcp_snd_nxt);
}

void
tcp_init(void) {
	tcb_count = 1;

	tcbs[0].tcp_state = TCP_STATE_LISTEN;
	tcbs[0].tcp_local_port = 8000;
}

void
handle_tcp(uint8_t *macSource, uint8_t *sourceAddr, uint8_t *destIPAddr, uint16_t length, DATA_CB dataCb, void *priv)
{
	uint8_t buf[length];

	dataCb(buf, length, priv);

	uart_puts("TCP\n");

	uint16_t sourcePort = ((buf[0] & 0xFF) << 8) | buf[1] & 0xFF;
	uint16_t destPort = ((buf[2] & 0xFF) << 8) | buf[3] & 0xFF;
	uint32_t seqNo = CONV_32(buf+4);
	uint32_t ackNo = CONV_32(buf+8);
	uint8_t dataOffset = (buf[12] & 0xF0 )>> 4; // in 4-byte value
	uint8_t flags = buf[13];
	uint16_t window = CONV_16(buf+14);
	uint16_t cs = CONV_16(buf+16);

#if 0
	printf("Surce port: %d\n", sourcePort);
	printf("Dest port : %d\n", destPort);
	printf("SeqNo: %u\n", seqNo);
	printf("ackNo: %u\n", ackNo);
	printf("Data offset: %d\n", dataOffset);
	printf("Flags: ");
	if( flags & TCP_FIN ) {
		printf("FIN, ");
	}
	if( flags & TCP_SYN ) {
		printf("SYN, ");
	}
	if( flags & TCP_RST) {
		printf("RST, ");
	}
	if( flags & TCP_ACK) {
		printf("ACK, ");
	}
	printf("\n");
	printf("Window: %d\n", window);
	printf("Checksum: %d\n", cs);
#endif
	/* Parse options */
	uint8_t *op = buf+20;
	while(op < buf+dataOffset*4) {
		//printf("Option: %d\n", op[0]);
		if( op[0] == 0x0) {
			break;
		}
		switch(op[0]) {
			case 1:
				op++;
				break;
			case 2:
				//printf("Maximum segment size: %d\n", CONV_16(op+2));
				op += 4;
				break;
			default:
				op += op[1];
				break;
		}
	}

	// Find TCB by local_port
	struct tcb *tcb = NULL;
	for(int i=0;i<tcb_count; i++) {
		if ( destPort == tcbs[i].tcp_local_port) {
			tcb = &tcbs[i];
			break;
		}
	}

	uint32_t data_length = length-(dataOffset*4);

	if( tcb == NULL ) {
		//printf("TCB is closed\n");
		/* CLOSED state handling according to STD7 p. 65 */
		struct tcb ttcb;
		uint16_t rflags = TCP_RST;

		if ( flags & TCP_ACK ) {
			ttcb.tcp_snd_nxt = ackNo;
		} else {
			ttcb.tcp_snd_nxt = 0;
			ttcb.tcp_rcv_nxt = seqNo + data_length;
			rflags |= TCP_ACK;
		}
		tcp_send(&ttcb, rflags, null_mac, 0);

		return;
	}

	if ( tcb->tcp_state == TCP_STATE_LISTEN) {
		if ( flags & TCP_RST ) {
			return;
		}
		if ( flags & TCP_ACK ) {
			tcb->tcp_snd_nxt = ackNo;
			tcp_send(tcb, TCP_RST, null_mac, 0);
			return;
		}

		if ( flags & TCP_SYN ) {
			memcpy(tcb->local_addr, destIPAddr, 16);
			memcpy(tcb->remote_addr, sourceAddr, 16);
			tcb->tcp_state = TCP_STATE_SYN_RECEIVED;
			tcb->tcp_remote_port = sourcePort;

			/* Initialize variables from the received SYN-packet */
			tcb->tcp_irs = seqNo;
			tcb->tcp_rcv_wnd = RECV_WINDOW;
			tcb->tcp_rcv_nxt = seqNo + 1;

			/* Initialize variables for sending */
			tcb->tcp_iss = 312;
			tcb->tcp_snd_wnd = window;
			tcb->tcp_snd_una = tcb->tcp_iss;
			tcb->tcp_snd_nxt = tcb->tcp_iss + 1;

			tcp_send(tcb, TCP_SYN | TCP_ACK, null_mac, 0);
		}
	}

	/* TODO: Add SYN-SENT handling */

	if ( data_length == 0 ) {
		/* Add the two zero case handlings */
	} else {
		//if ( tcb->tcp_rcv_wnd
	}
	/* TODO: Add window check and deal with out-of order and
		 lost packages */


	switch(tcb->tcp_state) {
		case TCP_STATE_SYN_RECEIVED:
			if (flags & TCP_RST) {
				tcb->tcp_state = TCP_STATE_LISTEN;
				return;
			}
			if (flags & TCP_ACK) {
				tcb->tcp_state = TCP_STATE_ESTABLISHED;
			}
			break;

		case TCP_STATE_ESTABLISHED:
			if (flags & TCP_RST) {
				/* TODO: Add proper RST handling */
				tcb->tcp_state = TCP_STATE_LISTEN;
				return;
			}
			if ( flags & TCP_ACK ) {
				tcb->tcp_snd_una = ackNo;
				tcb->tcp_rcv_nxt = seqNo;
			}
			/* Echo data back ack'ing things along the way */
			tcp_send(tcb, TCP_ACK, buf+dataOffset*4, data_length);
			break;
	}

	//printf("Packet contains %d bytes of data\n", data_length);
}
#endif
