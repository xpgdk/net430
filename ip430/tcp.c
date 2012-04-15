#ifdef HAVE_TCP
#include <stdint.h>
#include <string.h>

#include "tcp.h"
#include "stack.h"
#include "debug.h"
#include "mem.h"

#define TCP_STATE_NONE		0
#define TCP_STATE_LISTEN	1
#define TCP_STATE_SYN_SENT	2
#define TCP_STATE_SYN_RECEIVED 	3
#define TCP_STATE_ESTABLISHED	4
#define TCP_STATE_CLOSE_WAIT	5
#define TCP_STATE_LAST_ACK	6

#define RECV_WINDOW		200

//static struct tcb tcbs[1];
static uint16_t tcb_id;
static uint16_t tcb_count;

/**
TODO: Add retransmission queue and a timer tick to retransmit packages
*/

void
tcp_send(struct tcb *tcb, uint16_t flags, uint32_t count) {
	struct ipv6_packet_arg arg;
	uint8_t buf[20];

	arg.dst_mac_addr = null_mac;
	arg.dst_ipv6_addr = tcb->remote_addr;
	arg.src_ipv6_addr = tcb->local_addr;
	arg.payload_length = SIZE_TCP_HEADER + count;
	arg.protocol = PROTO_TCP;

	net_start_ipv6_packet(&arg);

	buf[0] = (tcb->tcp_local_port >> 8) & 0xFF;
	buf[1] = tcb->tcp_local_port & 0xFF;
	buf[2] = (tcb->tcp_remote_port >> 8) & 0xFF;
	buf[3] = (tcb->tcp_remote_port & 0xFF);
	CONV_OUT_32(buf+4, tcb->tcp_snd_nxt); // Sequence 
	CONV_OUT_32(buf+8, tcb->tcp_rcv_nxt); // Ack
	buf[12] = 0x05 << 4; // Data offset
	buf[13] = flags;
	CONV_OUT_16(buf+14, RECV_WINDOW);
	net_send_data(buf, 16);
	calc_checksum(buf, 16);

	buf[0] = buf[1] = 0x00; // Checksum
	net_send_dummy_checksum();

	net_send_data(buf, 2);

	//net_send_data(buf, 20);
	/*net_send_data(data, count);

	net_end_ipv6_packet();*/

	if( count > 0 ) {
		tcb->tcp_snd_nxt += count;
	} else if (flags & TCP_ACK) {
		tcb->tcp_snd_nxt++;
	}

	//printf("Next sequence number: %d\n", tcb->tcp_snd_nxt);
}

void
net_tcp_end_packet(void) {
	net_send_replace_checksum(~checksum);
	net_end_ipv6_packet();
}

void
tcp_init(void) {
	tcb_count = 5;

	tcb_id = mem_alloc(sizeof(struct tcb)*tcb_count);

	struct tcb tcb;

	for(int i=0;i<tcb_count;i++) {
		tcb.tcp_state = TCP_STATE_NONE;
		mem_write(tcb_id, i*sizeof(struct tcb), (uint8_t*)&tcb, sizeof(struct tcb));
	}
	tcb.tcp_state = TCP_STATE_LISTEN;
	tcb.tcp_local_port = 8000;
	mem_write(tcb_id, 0, &tcb, sizeof(struct tcb));
}

void
handle_tcp(uint8_t *macSource, uint8_t *sourceAddr, uint8_t *destIPAddr, uint16_t length, DATA_CB dataCb, void *priv)
{
	/* Enough to keep the TCP header without options */
	uint8_t buf[20];

	dataCb(buf, 20, priv);

	debug_puts("TCP");
	debug_nl();

	uint16_t sourcePort = ((buf[0] & 0xFF) << 8) | buf[1] & 0xFF;
	uint16_t destPort = ((buf[2] & 0xFF) << 8) | buf[3] & 0xFF;
	uint32_t seqNo = CONV_32(buf+4);
	uint32_t ackNo = CONV_32(buf+8);
	uint8_t dataOffset = (buf[12] & 0xF0 )>> 4; // in 4-byte value
	uint8_t flags = buf[13];
	uint16_t window = CONV_16(buf+14);
	uint16_t cs = CONV_16(buf+16);

#if 1
	debug_puts("Source port: ");
	debug_puthex(sourcePort);
	debug_nl();
	debug_puts("Dest   port: ");
	debug_puthex(destPort);
	debug_nl();
	debug_puts("SeqNo: ");
	debug_puthex(seqNo);
	debug_nl();
#endif
	debug_puts("Flags: ");
	if( flags & TCP_FIN ) {
		debug_puts("FIN, ");
	}
	if( flags & TCP_SYN ) {
		debug_puts("SYN, ");
	}
	if( flags & TCP_RST) {
		debug_puts("RST, ");
	}
	if( flags & TCP_ACK) {
		debug_puts("ACK, ");
	}
	debug_nl();
	/* Parse options */
	uint8_t op;
	uint16_t read;
	while(read < dataOffset*4) {
		dataCb(&op, 1, priv);
		read++;
		if( op == 0x0) {
			break;
		}
		switch(op) {
			case 1:
				//dataCb(&op, 1, priv);
				break;
			case 2:
				//printf("Maximum segment size: %d\n", CONV_16(op+2));
				for(int i=0;i<3; i++)
					dataCb(&op, 1, priv);
				read+= 3;
				break;
			default:
				dataCb(&op, 1, priv);
				read += op+1;
				for(int i=0;i<op; i++)
					dataCb(&op, 1, priv);
				break;
		}
	}

	// Find TCB by local_port
	struct tcb tcb;
	uint16_t tcb_no;
	tcb.tcp_state = TCP_STATE_NONE;
	for(int i=0;i<tcb_count; i++) {
		mem_read(tcb_id, i*sizeof(struct tcb), &tcb, sizeof(struct tcb));
		if ( tcb.tcp_state != TCP_STATE_NONE && destPort == tcb.tcp_local_port) {
			tcb_no = i;
			break;
		}
	}

	uint32_t data_length = length-(dataOffset*4);

	debug_puts("State: ");
	debug_puthex(tcb.tcp_state);
	debug_nl();

	if( tcb.tcp_state == TCP_STATE_NONE ) {
		debug_puts("TCB Closed");
		debug_nl();
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
		tcp_send(&ttcb, rflags, 0);
		net_tcp_end_packet();

		return;
	}

	if ( tcb.tcp_state == TCP_STATE_LISTEN) {
		if ( flags & TCP_RST ) {
			return;
		}
		if ( flags & TCP_FIN ) {
			return;
		}
		if ( flags & TCP_ACK ) {
			tcb.tcp_snd_nxt = ackNo;
			tcp_send(&tcb, TCP_RST, 0);
			net_tcp_end_packet();
			/* Update TCB */
			mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb, sizeof(struct tcb));
			return;
		}

		if ( flags & TCP_SYN ) {
			memcpy(tcb.local_addr, destIPAddr, 16);
			memcpy(tcb.remote_addr, sourceAddr, 16);
			tcb.tcp_state = TCP_STATE_SYN_RECEIVED;
			tcb.tcp_remote_port = sourcePort;

			/* Initialize variables from the received SYN-packet */
			tcb.tcp_irs = seqNo;
			tcb.tcp_rcv_wnd = RECV_WINDOW;
			tcb.tcp_rcv_nxt = seqNo + 1;

			/* Initialize variables for sending */
			tcb.tcp_iss = 312;
			tcb.tcp_snd_wnd = window;
			tcb.tcp_snd_una = tcb.tcp_iss;
			tcb.tcp_snd_nxt = tcb.tcp_iss + 1;

			tcp_send(&tcb, TCP_SYN | TCP_ACK, 0);
			net_tcp_end_packet();
			/* Update TCB */
			mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb, sizeof(struct tcb));
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


	switch(tcb.tcp_state) {
		case TCP_STATE_SYN_RECEIVED:
			if (flags & TCP_RST) {
				tcb.tcp_state = TCP_STATE_LISTEN;
				/* Update TCB */
				mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb, sizeof(struct tcb));
				return;
			}
			if (flags & TCP_ACK) {
				tcb.tcp_state = TCP_STATE_ESTABLISHED;
				/* Update TCB */
				mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb, sizeof(struct tcb));
			}
			break;

		case TCP_STATE_CLOSE_WAIT:
		case TCP_STATE_ESTABLISHED:
			if (flags & TCP_FIN) {
				tcb.tcp_rcv_nxt = seqNo;
				tcp_send(&tcb, TCP_ACK | TCP_FIN, 0);
				net_tcp_end_packet();
				tcb.tcp_state = TCP_STATE_NONE;
				/* Update TCB */
				mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb, sizeof(struct tcb));
				return;
			}
			if (flags & TCP_RST) {
				/* TODO: Add proper RST handling */
				tcb.tcp_state = TCP_STATE_LISTEN;
				/* Update TCB */
				mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb, sizeof(struct tcb));
				return;
			}
			if ( flags & TCP_ACK ) {
				debug_puts("Updating ack");
				debug_nl();
				tcb.tcp_snd_una = ackNo;
				tcb.tcp_rcv_nxt = seqNo + data_length;
			}
			/* Echo data back ack'ing things along the way */
			if (data_length > 0) {
				tcp_send(&tcb, TCP_ACK, data_length);
				for(int i=0; i<data_length; i+=20) {
					uint16_t count = 20;
					if (i+count > data_length) {
						count = data_length - i;
					}
					dataCb(buf, count, priv);
					net_send_data(buf, count);
					calc_checksum(buf, count);
				}
				net_tcp_end_packet();
			}
			/* Update TCB */
			mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb, sizeof(struct tcb));
			break;
	}

	//printf("Packet contains %d bytes of data\n", data_length);
}
#endif
