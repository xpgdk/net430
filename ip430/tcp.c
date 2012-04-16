#ifdef HAVE_TCP
#include <stdint.h>
#include <string.h>

#include "tcp.h"
#include "stack.h"
#include "debug.h"
#include "mem.h"

#define RECV_WINDOW		200

static uint16_t tcb_id;
static uint16_t tcb_count;

/**
 TODO: Add retransmission queue and a timer tick to retransmit packages.
 We won't be keeping received packets, as we require them to be in-order
 */

/*
 * TODO: Add ack-timer: When receiving data, it is ack'ed on next transmitted data.
 * However, if no data is transmitted before the ack-timeout, the data must be ack'ed
 * explictly (i.e. not piggy bagged in a data packet).
 */

void tcp_send_packet(struct tcb *tcb, uint16_t flags, uint32_t count) {
	struct ipv6_packet_arg arg;
	uint8_t buf[4];

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
	net_send_data(buf, 4);
	calc_checksum(buf, 4);

	CONV_OUT_32(buf, tcb->tcp_snd_nxt); // Sequence
	net_send_data(buf, 4);
	calc_checksum(buf, 4);

	CONV_OUT_32(buf, tcb->tcp_rcv_nxt); // Ack
	net_send_data(buf, 4);
	calc_checksum(buf, 4);

	buf[0] = 0x05 << 4; // Data offset
	buf[1] = flags;
	CONV_OUT_16(buf + 2, RECV_WINDOW);
	net_send_data(buf, 4);
	calc_checksum(buf, 4);

	buf[0] = buf[1] = 0x00; // Checksum
	net_send_dummy_checksum();

	net_send_data(buf, 2);

	//net_send_data(buf, 20);
	/*net_send_data(data, count);

	 net_end_ipv6_packet();*/

	if (count > 0) {
		tcb->tcp_snd_nxt += count;
	} else if (flags & TCP_ACK) {
		tcb->tcp_snd_nxt++;
	}

	//printf("Next sequence number: %d\n", tcb->tcp_snd_nxt);
}

void net_tcp_end_packet(void) {
	net_send_replace_checksum(~checksum);
	net_end_ipv6_packet();
}

void tcp_init(void) {
	tcb_count = 5;

	tcb_id = mem_alloc(sizeof(struct tcb) * tcb_count);

	struct tcb tcb;

	for (int i = 0; i < tcb_count; i++) {
		tcb.tcp_state = TCP_STATE_NONE;
		mem_write(tcb_id, i * sizeof(struct tcb), (uint8_t*) &tcb,
				sizeof(struct tcb));
	}
	/*	tcb.tcp_state = TCP_STATE_LISTEN;
	 tcb.tcp_local_port = 8000;*/
	mem_write(tcb_id, 0, &tcb, sizeof(struct tcb));
}

void handle_tcp(uint8_t *macSource, uint8_t *sourceAddr, uint8_t *destIPAddr,
		uint16_t length, DATA_CB dataCb, void *priv) {
	uint8_t buf[4];

	debug_puts("TCP");
	debug_nl();

	dataCb(buf, 2, priv);
	uint16_t sourcePort = ((buf[0] & 0xFF) << 8) | (buf[1] & 0xFF);

	dataCb(buf, 2, priv);
	uint16_t destPort = ((buf[0] & 0xFF) << 8) | (buf[1] & 0xFF);

	dataCb(buf, 4, priv);
	uint32_t seqNo = CONV_32(buf);

	dataCb(buf, 4, priv);
	uint32_t ackNo = CONV_32(buf);

	dataCb(buf, 2, priv);
	uint8_t dataOffset = (buf[0] & 0xF0) >> 4; // in 4-byte value
	uint8_t flags = buf[1];

	dataCb(buf, 2, priv);
	uint16_t window = CONV_16(buf);

	dataCb(buf, 2, priv);
	//uint16_t cs = CONV_16(buf);

#if 1
	debug_puts("Source port: ");
	debug_puthex(sourcePort);
	debug_nl();
	debug_puts("Dest   port: ");
	debug_puthex(destPort);
	debug_nl();
	debug_puts("SeqNo: ");
	debug_puthex(seqNo >> 16);
	debug_puthex(seqNo & 0xFFFF);
	debug_nl();
#endif
	debug_puts("Flags: ");
	if (flags & TCP_FIN) {
		debug_puts("FIN, ");
	}
	if (flags & TCP_SYN) {
		debug_puts("SYN, ");
	}
	if (flags & TCP_RST) {
		debug_puts("RST, ");
	}
	if (flags & TCP_ACK) {
		debug_puts("ACK, ");
	}
	debug_nl();
	/* Parse options */
	uint8_t op;
	uint16_t read;
	while (read < dataOffset * 4) {
		dataCb(&op, 1, priv);
		read++;
		if (op == 0x0) {
			break;
		}
		switch (op) {
		case 1:
			//dataCb(&op, 1, priv);
			break;
		case 2:
			//printf("Maximum segment size: %d\n", CONV_16(op+2));
			for (int i = 0; i < 3; i++)
				dataCb(&op, 1, priv);
			read += 3;
			break;
		default:
			dataCb(&op, 1, priv);
			read += op + 1;
			for (int i = 0; i < op; i++)
				dataCb(&op, 1, priv);
			break;
		}
	}

	// Find TCB by local_port
	struct tcb tcb;
	uint16_t tcb_no;
	tcb.tcp_state = TCP_STATE_NONE;
	for (int i = 0; i < tcb_count; i++) {
		mem_read(tcb_id, i * sizeof(struct tcb), &tcb, sizeof(struct tcb));
		if (tcb.tcp_state != TCP_STATE_NONE && destPort == tcb.tcp_local_port) {
			tcb_no = i;
			break;
		}
	}

	uint32_t data_length = length - (dataOffset * 4);

	debug_puts("State: ");
	debug_puthex(tcb.tcp_state);
	debug_nl();

	if (tcb.tcp_state == TCP_STATE_NONE || tcb.tcp_state == TCP_STATE_CLOSED) {
		debug_puts("TCB Closed");
		debug_nl();
		/* CLOSED state handling according to STD7 p. 65 */
		struct tcb ttcb;
		uint16_t rflags = TCP_RST;

		memcpy(ttcb.local_addr, destIPAddr, 16);
		memcpy(ttcb.remote_addr, sourceAddr, 16);
		ttcb.tcp_remote_port = sourcePort;
		ttcb.tcp_local_port = destPort;

		if (flags & TCP_ACK) {
			ttcb.tcp_snd_nxt = ackNo;
		} else {
			ttcb.tcp_snd_nxt = 0;
			ttcb.tcp_rcv_nxt = seqNo + data_length;
			rflags |= TCP_ACK;
		}
		if ( (flags & TCP_SYN) && data_length == 0) {
			ttcb.tcp_rcv_nxt = seqNo + 1;
		}
		tcp_send_packet(&ttcb, rflags, 0);
		net_tcp_end_packet();

		return;
	}

	if (tcb.tcp_state == TCP_STATE_LISTEN) {
		if (flags & TCP_RST) {
			return;
		}
		if (flags & TCP_FIN) {
			return;
		}
		if (flags & TCP_ACK) {
			tcb.tcp_snd_nxt = ackNo;
			tcp_send_packet(&tcb, TCP_RST, 0);
			net_tcp_end_packet();
			/* Update TCB */
			mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb,
					sizeof(struct tcb));
			return;
		}

		if (flags & TCP_SYN) {
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

			tcp_send_packet(&tcb, TCP_SYN | TCP_ACK, 0);
			net_tcp_end_packet();
			debug_puts("TCP Send");
			debug_nl();
			/* Update TCB */
			mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb,
					sizeof(struct tcb));
			debug_puts("TCB updated");
			debug_nl();
			return;
		}
	}

	/* TODO: Add SYN-SENT handling */

	if (data_length == 0) {
		/* Add the two zero case handlings */
	} else {
		//if ( tcb->tcp_rcv_wnd
	}
	/* TODO: Add window check and deal with out-of order and
	 lost packages */

	switch (tcb.tcp_state) {
	case TCP_STATE_LAST_ACK:
		if (flags & TCP_ACK) {
			tcb.tcp_state = TCP_STATE_CLOSED;
			/* Update TCB */
			mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb,
					sizeof(struct tcb));
			tcb.callback(tcb_no, tcb.tcp_state, 0, NULL, NULL);
		}
		break;
	case TCP_STATE_SYN_RECEIVED:
		if (flags & TCP_RST) {
			tcb.tcp_state = TCP_STATE_LISTEN;
			/* Update TCB */
			mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb,
					sizeof(struct tcb));
			return;
		}
		if (flags & TCP_ACK) {
			tcb.tcp_state = TCP_STATE_ESTABLISHED;
			tcb.callback(tcb_no, tcb.tcp_state, 0, NULL, NULL);
			/* Update TCB */
			mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb,
					sizeof(struct tcb));
		}
		break;

	case TCP_STATE_CLOSE_WAIT:
	case TCP_STATE_ESTABLISHED:
		if (flags & TCP_FIN) {
			tcb.tcp_rcv_nxt = seqNo + 1;
			tcp_send_packet(&tcb, TCP_ACK, 0);
			net_tcp_end_packet();
			tcb.tcp_snd_nxt--;

			tcp_send_packet(&tcb, TCP_ACK | TCP_FIN, 0);
			net_tcp_end_packet();

			tcb.tcp_state = TCP_STATE_LAST_ACK;
			/* Update TCB */
			mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb,
					sizeof(struct tcb));
			return;
		}
		if (flags & TCP_RST) {
			/* TODO: Add proper RST handling */
			tcb.tcp_state = TCP_STATE_LISTEN;
			/* Update TCB */
			mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb,
					sizeof(struct tcb));
			return;
		}
		if (flags & TCP_ACK) {
			debug_puts("Updating ack");
			debug_nl();
			tcb.tcp_snd_una = ackNo;
			tcb.tcp_rcv_nxt = seqNo + data_length;
		}
		/* Echo data back ack'ing things along the way */
		if (data_length > 0) {
			tcb.callback(tcb_no, tcb.tcp_state, data_length, dataCb, priv);
//				tcp_send(&tcb, TCP_ACK, data_length);
//				for(int i=0; i<data_length; i+=20) {
//					uint16_t count = 20;
//					if (i+count > data_length) {
//						count = data_length - i;
//					}
//					dataCb(buf, count, priv);
//					net_send_data(buf, count);
//					calc_checksum(buf, count);
//				}
//				net_tcp_end_packet();
		}
		/* Update TCB */
		mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb,
				sizeof(struct tcb));
		break;
	}

	//printf("Packet contains %d bytes of data\n", data_length);
}

int tcp_socket(tcp_callback callback) {
	struct tcb tcb;
	int socket = -1;

	for (int i = 0; i < tcb_count; i++) {
		//	tcb.tcp_state = TCP_STATE_NONE;
		mem_read(tcb_id, i * sizeof(struct tcb), (uint8_t*) &tcb,
				sizeof(struct tcb));
		if (tcb.tcp_state == TCP_STATE_NONE) {
			tcb.tcp_state = TCP_STATE_CLOSED;

			tcb.callback = callback;
			socket = i;
			mem_write(tcb_id, i * sizeof(struct tcb), (uint8_t*) &tcb,
					sizeof(struct tcb));
			break;
		}
	}
	return socket;
}

void tcp_listen(int socket, uint16_t port) {
	struct tcb tcb;
	mem_read(tcb_id, socket * sizeof(struct tcb), (uint8_t*) &tcb,
			sizeof(struct tcb));
	tcb.tcp_local_port = port;
	tcb.tcp_state = TCP_STATE_LISTEN;
	mem_write(tcb_id, socket * sizeof(struct tcb), (uint8_t*) &tcb,
			sizeof(struct tcb));
}

void tcp_send(int socket, const uint8_t *buf, uint16_t count) {
	struct tcb tcb;
	mem_read(tcb_id, socket * sizeof(struct tcb), (uint8_t*) &tcb,
			sizeof(struct tcb));

	tcp_send_packet(&tcb, TCP_ACK, count);
	mem_write(tcb_id, socket * sizeof(struct tcb), (uint8_t*) &tcb,
			sizeof(struct tcb));

	net_send_data(buf, count);
	calc_checksum(buf, count);
	net_tcp_end_packet();
}

#endif
