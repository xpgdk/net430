#ifdef HAVE_TCP
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "tcp.h"
#include "stack.h"
#include "debug.h"
#include "mem.h"

#define RECV_WINDOW		1500
#define TCB_COUNT 10

static uint16_t tcb_id;
uint32_t tcp_initialSeqNo;


/**
 TODO: Add retransmission queue and a timer tick to retransmit packages.
 We won't be keeping received packets, as we require them to be in-order
 */

/*
 * TODO: Add ack-timer: When receiving data, it is ack'ed on next transmitted data.
 * However, if no data is transmitted before the ack-timeout, the data must be ack'ed
 * explictly (i.e. not piggy bagged in a data packet).
 */

void tcp_send_packet(struct tcb *tcb, uint16_t flags) {
	struct ipv6_packet_arg arg;
	uint8_t buf[4];

	CHECK_SP("tcp_send_packet: ");

#ifdef DEBUG_TCP
	debug_puts("Send Flags: ");
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
#endif

	arg.dst_mac_addr = null_mac;
	arg.dst_ipv6_addr = tcb->remote_addr;
	arg.src_ipv6_addr = tcb->local_addr;
	//arg.payload_length = SIZE_TCP_HEADER + count;
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

	//printf("Next sequence number: %d\n", tcb->tcp_snd_nxt);
}

/*
 * Due to overflow, we can only reliable compare timestamps
 * 5 hours appart
 * */
int
tcp_compare_time(uint16_t t1, uint16_t t2) {
	uint16_t diff = t1 > t2 ? t1-t2 : t2-t1;

	debug_puts("tcp_compare_time(");
	debug_puthex(t1);
	debug_puts(",");
	debug_puthex(t2);
	debug_puts(")");
	debug_nl();

	debug_puts("diff = ");
	debug_puthex(diff);
	debug_nl();
	if( diff == 0) {
		return 0;
	}

	if( diff > 18000 ) {
		/* Assume that one of the values has wrapped, meaning that the
		 * smallest one is actually the largest */
		if( t1 > t2 ) {
			return -1;
		} else {
			return 1;
		}
	} else {
		/* Assume that no wrapping has occured */
		if( t1 > t2 ) {
			return 1;
		} else {
			return -1;
		}
	}
}

void
tcp_timeout(uint16_t timeValue) {
	/* Do any time-related tasks.
	 * Overflows must be taken into account. */

	/* First check for inactive TCBs */
	struct tcb tcb;
	for (int i = 0; i < TCB_COUNT; i++) {

		debug_puts("TCB ");
		debug_puthex(i);
		debug_puts(": ");

		mem_read(tcb_id, i * sizeof(struct tcb), &tcb, sizeof(struct tcb));
		debug_puthex(tcb.tcp_state);
		debug_nl();
		switch(tcb.tcp_state) {
		case TCP_STATE_ESTABLISHED:
			debug_puts("Doing TCP timeout check");
			debug_nl();
			if(tcp_compare_time(timeValue, tcb.tcp_timeout) > 0) {
				/* Send keep-alive */
				debug_puts("Sending TCP keep-alive");
				debug_nl();
				tcp_send_packet(&tcb, TCP_ACK);

				net_tcp_end_packet(&tcb);

				mem_write(tcb_id, i* sizeof(struct tcb), (uint8_t*) &tcb,
						sizeof(struct tcb));
			}
			break;
		case TCP_STATE_TIME_WAIT:
			debug_puts("Doing STATE-TIME-WAIT timeout check");
			debug_nl();
			if(tcp_compare_time(timeValue, tcb.tcp_timeout) >= 0) {
				debug_puts("Moving to closed state");
				debug_nl();
				tcb.tcp_state = TCP_STATE_CLOSED;
				mem_write(tcb_id, i* sizeof(struct tcb), (uint8_t*) &tcb,
						sizeof(struct tcb));
				tcb.callback(i, tcb.tcp_state, 0, NULL, NULL);
			}
			break;
		}
	}

}

void net_tcp_end_packet(struct tcb *tcb) {
	uint16_t length = net_get_length()
			- (SIZE_ETHERNET_HEADER + SIZE_IPV6_HEADER + SIZE_TCP_HEADER);

	CHECK_SP("net_tcp_end_packet: ");
	if (length > 0) {
		tcb->tcp_snd_nxt += length;
	}

	//net_send_replace_checksum(~checksum);
	net_end_ipv6_packet();
}

void tcp_init(void) {
	tcp_initialSeqNo = rand() + (rand() << 16);

	debug_puts("Initial sequence number: ");
	debug_puthex(tcp_initialSeqNo >> 16);
	debug_puthex(tcp_initialSeqNo & 0xFFFF);
	debug_nl();

	debug_puts("TCB Size: ");
	debug_puthex(sizeof(struct tcb));
	debug_nl();

	tcb_id = mem_alloc(sizeof(struct tcb) * TCB_COUNT);

	struct tcb tcb;

	for (int i = 0; i < TCB_COUNT; i++) {
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
	CHECK_SP("handle_tcp, entry: ");
#ifdef DEBUG_TCP
	PRINT_SP("in handle_tcp: ");

	debug_puts("TCP");
	debug_nl();
#endif

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

#ifdef DEBUG_TCP
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
#endif

	/* Parse options */
	uint8_t op;
	uint16_t read = 0x11;
	while (read < dataOffset * 4) {
		dataCb(&op, 1, priv);
		read++;
		if (op == 0x0) {
			dataCb(&op, 1, priv);
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
	uint16_t tcb_no = 0xFFFF;
	tcb.tcp_state = TCP_STATE_NONE;
	for (int i = 0; i < TCB_COUNT; i++) {
		mem_read(tcb_id, i * sizeof(struct tcb), &tcb, sizeof(struct tcb));
		if (tcb.tcp_state == TCP_STATE_LISTEN
				&& destPort == tcb.tcp_local_port) {
			tcb_no = i;
			break;
		} else if (tcb.tcp_state != TCP_STATE_NONE
				&& destPort == tcb.tcp_local_port
				&& sourcePort == tcb.tcp_remote_port) {
			tcb_no = i;
			break;
		}
	}

	if( tcb_no == 0xFFFF ) {
		debug_puts("No TCB found, ignoring packet");
		debug_nl();
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

		// Ensure that we handle it as a TCB in CLOSED state
		tcb.tcp_state = TCP_STATE_NONE;
	}

	uint32_t data_length = length - (dataOffset * 4);

	CHECK_SP("handle_tcp, middle: ");

#ifdef DEBUG_TCP
	debug_puts("State: ");
	debug_puthex(tcb.tcp_state);
	debug_nl();
#endif

	if (tcb.tcp_state == TCP_STATE_NONE || tcb.tcp_state == TCP_STATE_CLOSED) {
#ifdef DEBUG_TCP
		debug_puts("TCB Closed");
		debug_nl();
#endif
		/* CLOSED state handling according
		debug_puts("") to STD7 p. 65 */
		struct tcb ttcb;
		uint16_t rflags = TCP_RST;

		memcpy(ttcb.local_addr, destIPAddr, 16);
		memcpy(ttcb.remote_addr, sourceAddr, 16);
		ttcb.tcp_remote_port = sourcePort;
		ttcb.tcp_local_port = destPort;

		if (flags & TCP_ACK) {
			ttcb.tcp_snd_nxt = ackNo;
			ttcb.tcp_rcv_nxt = 0;
		} else {
			ttcb.tcp_snd_nxt = 0;
			ttcb.tcp_rcv_nxt = seqNo + data_length;
			rflags |= TCP_ACK;
		}
		if ((flags & TCP_SYN) && data_length == 0) {
			ttcb.tcp_rcv_nxt = seqNo + 1;
		}
		tcp_send_packet(&ttcb, rflags);
		net_tcp_end_packet(&ttcb);

		return;
	}

	/* TODO: Add window check and deal with out-of order and
	 lost packages */

	if( tcb.tcp_state == TCP_STATE_SYN_RECEIVED ||
			tcb.tcp_state == TCP_STATE_ESTABLISHED ||
			tcb.tcp_state == TCP_STATE_FIN_WAIT_1 ||
			tcb.tcp_state == TCP_STATE_FIN_WAIT_2 ||
			tcb.tcp_state == TCP_STATE_TIME_WAIT) {
		bool ok = false;
		if (data_length == 0) {
			if( seqNo == tcb.tcp_rcv_nxt )
				ok = true;
		} else {
			uint32_t ma = tcb.tcp_rcv_nxt + RECV_WINDOW-1;
			uint32_t s = seqNo + data_length-1;
			if ( tcp_in_window(&seqNo, &tcb.tcp_rcv_nxt, &ma) ) {
				ok = true;
			} else if(tcp_in_window(&s, &s, &ma)) {
				ok = true;
			}
		}

		if( !ok ) {
			debug_puts("Segment check failed");
			debug_nl();
			if( flags & TCP_RST) {
				return;
			} else {
				tcp_send_packet(&tcb, TCP_ACK);
				net_tcp_end_packet(&tcb);
			}
			return;
		}
	}

	switch (tcb.tcp_state) {
	case TCP_STATE_LISTEN:
		if (flags & TCP_RST) {
			return;
		}
		if (flags & TCP_FIN) {
			return;
		}
		if (flags & TCP_ACK) {
			tcb.tcp_snd_nxt = ackNo;
			tcp_send_packet(&tcb, TCP_RST);
			net_tcp_end_packet(&tcb);
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
			//tcb.tcp_irs = seqNo;
			//tcb.tcp_rcv_wnd = RECV_WINDOW;
			tcb.tcp_rcv_nxt = seqNo + 1;

			/* Initialize variables for sending */
			//tcb.tcp_iss = tcp_initialSeqNo;
			//tcb.tcp_snd_wnd = window;
			tcb.tcp_snd_una = tcp_initialSeqNo;
			tcb.tcp_snd_nxt = tcp_initialSeqNo + 1;

			tcp_send_packet(&tcb, TCP_SYN | TCP_ACK);
			net_tcp_end_packet(&tcb);
			tcb.tcp_snd_nxt++; // Due to SYN
			/* Update TCB */
			mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb,
					sizeof(struct tcb));
			return;
		}
		break;
	case TCP_STATE_SYN_SENT:
		if ( flags & TCP_ACK ) {
			if ( !tcp_in_window(&ackNo, &tcb.tcp_snd_una, &tcb.tcp_snd_nxt) ) {
				if ( flags & TCP_RST ) {
					return;
				}
				// Just set tcp_snd_nxt in order to havTIME_WAITe the proper seqNo
				tcb.tcp_snd_nxt = ackNo;
				tcp_send_packet(&tcb, TCP_RST);
				return;
			}
		}

		if ( flags & TCP_RST ) {
			tcb.tcp_state = TCP_STATE_CLOSED;
			/* Update TCB */
			mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb,
					sizeof(struct tcb));
			return;
		}

		if ( flags & TCP_SYN ) {
			//tcb.tcp_irs = seqNo;
			//tcb.tcp_rcv_wnd = RECV_WINDOW;
			tcb.tcp_rcv_nxt = seqNo + 1;
			if ( flags & TCP_ACK ) {
				tcb.tcp_snd_una = ackNo;
			}

			if (tcp_compare(&tcb.tcp_snd_una, &tcb.tcp_snd_nxt) >= 0) {
				tcb.tcp_state = TCP_STATE_ESTABLISHED;
				tcp_send_packet(&tcb, TCP_ACK);
				net_tcp_end_packet(&tcb);
			} else {
				tcb.tcp_state = TCP_STATE_SYN_RECEIVED;
				tcp_send_packet(&tcb, TCP_ACK|TCP_SYN);
				net_tcp_end_packet(&tcb);
			}

			/* Update TCB */
			mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb,
					sizeof(struct tcb));
			tcb.callback(tcb_no, tcb.tcp_state, 0, NULL, NULL);
		}
		break;
	case TCP_STATE_FIN_WAIT_2:
		if ((flags & TCP_ACK) && (flags & TCP_FIN)) {
			tcb.tcp_rcv_nxt = seqNo + 1;
			tcp_send_packet(&tcb, TCP_ACK);
			net_tcp_end_packet(&tcb);
			tcb.tcp_state = TCP_STATE_CLOSED;
			/* Update TCB */
			mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb,
					sizeof(struct tcb));
			tcb.callback(tcb_no, tcb.tcp_state, 0, NULL, NULL);
		} else 	if (flags & TCP_ACK) {
			tcb.tcp_state = TCP_STATE_TIME_WAIT;
			tcb.tcp_timeout = net_get_time() + 30; // Should be 4 minutes = (2 MSL)
			/* Update TCB */
			mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb,
					sizeof(struct tcb));
		}
		break;
	case TCP_STATE_TIME_WAIT:
		if ((flags & TCP_ACK) && (flags & TCP_FIN)) {
			tcb.tcp_rcv_nxt = seqNo + 1;
			tcp_send_packet(&tcb, TCP_ACK);
			net_tcp_end_packet(&tcb);
			tcb.tcp_state = TCP_STATE_CLOSED;
			/* Update TCB */
			mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb,
					sizeof(struct tcb));
			tcb.callback(tcb_no, tcb.tcp_state, 0, NULL, NULL);
		}
		break;
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
			tcp_send_packet(&tcb, TCP_ACK);
			net_tcp_end_packet(&tcb);
			//tcb.tcp_snd_nxt--;

			tcp_send_packet(&tcb, TCP_ACK | TCP_FIN);
			net_tcp_end_packet(&tcb);

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
			tcb.tcp_snd_una = ackNo;
			tcb.tcp_rcv_nxt = seqNo + data_length;
		}

		// We expect data at least every 30s
		// We will send keep-alives if we don't get them
		tcb.tcp_timeout = net_get_time() + 30;

		if (data_length > 0) {
			/* Update TCB */
			mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb,
					sizeof(struct tcb));
			tcb.callback(tcb_no, tcb.tcp_state, data_length, dataCb, priv);
		} else {
			/* Update TCB */
			mem_write(tcb_id, tcb_no * sizeof(struct tcb), &tcb,
					sizeof(struct tcb));
		}
		break;
	}

	//printf("Packet contains %d bytes of data\n", data_length);
}

int tcp_socket(tcp_callback callback) {
	struct tcb tcb;
	int socket = -1;

	CHECK_SP("tcp_socket ");

	for (int i = 0; i < TCB_COUNT; i++) {
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
	CHECK_SP("tcp_listen: ");
	mem_read(tcb_id, socket * sizeof(struct tcb), (uint8_t*) &tcb,
			sizeof(struct tcb));
	tcb.tcp_local_port = port;
	tcb.tcp_state = TCP_STATE_LISTEN;
	mem_write(tcb_id, socket * sizeof(struct tcb), (uint8_t*) &tcb,
			sizeof(struct tcb));
}

void tcp_send(int socket, const uint8_t *buf, uint16_t count) {
	struct tcb tcb;
	CHECK_SP("tcp_send: ");
	mem_read(tcb_id, socket * sizeof(struct tcb), (uint8_t*) &tcb,
			sizeof(struct tcb));

	tcp_send_packet(&tcb, TCP_ACK);

	net_send_data(buf, count);
	calc_checksum(buf, count);
	net_tcp_end_packet(&tcb);

	mem_write(tcb_id, socket * sizeof(struct tcb), (uint8_t*) &tcb,
			sizeof(struct tcb));
}

void tcp_send_start(int socket) {
	struct tcb tcb;
	CHECK_SP("tcp_send_start: ");
	mem_read(tcb_id, socket * sizeof(struct tcb), (uint8_t*) &tcb,
			sizeof(struct tcb));

	tcp_send_packet(&tcb, TCP_ACK);
	mem_write(tcb_id, socket * sizeof(struct tcb), (uint8_t*) &tcb,
			sizeof(struct tcb));
}

void tcp_send_data(const uint8_t *buf, uint16_t count) {
	CHECK_SP("tcp_send_data: ");
	net_send_data(buf, count);
	calc_checksum(buf, count);
}

void tcp_send_end(int socket) {
	struct tcb tcb;
	CHECK_SP("tcp_send_end: ");
	mem_read(tcb_id, socket * sizeof(struct tcb), (uint8_t*) &tcb,
			sizeof(struct tcb));

	net_tcp_end_packet(&tcb);

	mem_write(tcb_id, socket * sizeof(struct tcb), (uint8_t*) &tcb,
			sizeof(struct tcb));
}

void tcp_close(int socket) {
	struct tcb tcb;
	CHECK_SP("tcp_close: ");
	mem_read(tcb_id, socket * sizeof(struct tcb), (uint8_t*) &tcb,
			sizeof(struct tcb));

	tcp_send_packet(&tcb, TCP_FIN | TCP_ACK);
	net_tcp_end_packet(&tcb);
	tcb.tcp_state = TCP_STATE_FIN_WAIT_2;
	tcb.tcp_snd_nxt++;
	mem_write(tcb_id, socket * sizeof(struct tcb), (uint8_t*) &tcb,
			sizeof(struct tcb));
}

void tcp_connect(int socket, uint8_t *local_addr, uint8_t *remote_addr,
		uint16_t port) {
	struct tcb tcb;
	CHECK_SP("tcp_connect: ");
	mem_read(tcb_id, socket * sizeof(struct tcb), (uint8_t*) &tcb,
			sizeof(struct tcb));
	tcb.tcp_state = TCP_STATE_SYN_SENT;

	tcb.tcp_local_port = tcp_initialSeqNo & 0xFFFF;
	tcb.tcp_remote_port = port;
	memcpy(tcb.local_addr, local_addr, 16);
	memcpy(tcb.remote_addr, remote_addr, 16);
	//tcb.tcp_irs = 0;
	//tcb.tcp_rcv_wnd = RECV_WINDOW;
	tcb.tcp_rcv_nxt = 0;

	//tcb.tcp_iss = 8765;
	//tcb.tcp_snd_wnd = 0;
	tcb.tcp_snd_una = tcp_initialSeqNo;
	tcb.tcp_snd_nxt = tcp_initialSeqNo;

	tcp_send_packet(&tcb, TCP_SYN);
	net_tcp_end_packet(&tcb);
	tcb.tcp_snd_nxt++;
	mem_write(tcb_id, socket * sizeof(struct tcb), (uint8_t*) &tcb,
			sizeof(struct tcb));
}

bool
tcp_in_window(uint32_t *no, uint32_t *min, uint32_t *max) {
	// All three arguments overflow after 2**32 - 1
	// We need to take care of that when comparing.

	// There are two scenarios:
	// 1. No overflows / min overflows
	//     0 ---------|-----------------|------ 2**32 -1
	//               min               max
	//                 =================
	//                   valid region
	//
	// 2. Max overflows
	//     0 ---|---------------------------|-- 2**32 -1
	//         max                         min
	//       ===                             ==
	//    valid region 1                  valid region 2

	// Case 1
	if (*max >= *min ) {
		if( *no >= *min && *no <= *max) {
			return true;
		} else {
			return false;
		}
	}

	// Case 2
	if (*min > *max) {
		if( *no < *max || *no > *min ) {
			return true;
		}
	}

	return false;
}

int8_t
tcp_compare(uint32_t *no1, uint32_t *no2) {
	// Both no1 and no2 overflow after 2**32 -1
	// When we compare the two numbers, we assume that 
	// although an overflow has occoured, the two numbers are no
	// more than 2**30 from each other
	// Graphicallly, when no2 > no1 overflows looks like this:
	// 0 -----|---------------------------|--- 2**32 -1
	//       no2                         no1
	// As long as no1 - no2 < 2**30, no2 is largest.

	// Trivial case
	if(*no1 == *no2) {
		return 0;
	}

	uint32_t dist;

	if( *no1 > *no2 ) {
		dist = *no1 - *no2;
	} else {
		dist = *no2 - *no1;
	}

	if( dist > 0x40000000LL ) {
		if( *no1 > *no2 ) {
			return -1;
		} else {
			return 1;
		}
	} else {
		if( *no1 > *no2 ) {
			return 1;
		} else {
			return -1;
		}
	}
}

#endif
