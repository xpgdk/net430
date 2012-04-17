#include <msp430.h>
#include "uart.h"
#include "enc28j60.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "stack.h"
#include "spi.h"
#include "spi_mem.h"
#include "udp.h"
#include "tcp.h"

const uint8_t mac_addr[] = { 0xea, 0x75, 0xbf, 0x72, 0x0f, 0x3d };

static unsigned char gotChar = 0;
static bool gotData = false;
static bool closed = false;

void uart_rx_isr(unsigned char c) {
	gotChar = c;
}

void server_callback(int socket, uint8_t new_state, uint16_t count, DATA_CB data, void *priv) {
	debug_puts("State: ");
	debug_puthex(new_state);
	debug_nl();

	debug_puts("Data count: ");
	debug_puthex(count);
	debug_nl();

	if( count > 0) {
		gotData = true;
	}

	if( new_state == TCP_STATE_CLOSED) {
		closed = true;
	}
}

const static uint8_t dst[] = { 0x20, 0x01, 0x16, 0xd8, 0xdd, 0xaa, 0x00, 0x1,
		0x02, 0x23, 0x54, 0xff, 0xfe, 0xd5, 0x46, 0xf0 };

const static char myMessage[] = "Got your message, sir\n";

int main(void) {
	WDTCTL = WDTPW + WDTHOLD; // Stop WDT
	BCSCTL1 = CALBC1_12MHZ; // Set DCO
	DCOCTL = CALDCO_12MHZ;

	uart_init();

	unsigned char c;
	uart_getc(&c);

	// register ISR called when data was received
	uart_set_rx_isr_ptr(uart_rx_isr);

	__bis_SR_register(GIE);

	spi_init();

	spi_mem_init();

	enc_init(mac_addr);
	net_init(mac_addr);

	int server_sock = tcp_socket(server_callback);
	tcp_listen(server_sock, 8000);

	debug_puts("server_sock: ");
	debug_puthex(server_sock);
	debug_nl();

	while (1) {

		net_tick();
		if (!enc_idle) {
			enc_action();
		}

		if (gotData) {

			tcp_send(server_sock, myMessage, sizeof(myMessage));
			gotData = false;
		}

		if (closed) {
			tcp_listen(server_sock, 8000);
			closed = false;
		}

		if (gotChar != 0) {
			unsigned char c = gotChar;
			gotChar = 0;
			uint8_t addr[16];
			net_get_address(ADDRESS_STORE_MAIN_OFFSET, addr);
			struct udp_packet_header udpHeader;
			udpHeader.ipv6.dst_ipv6_addr = dst;
			udpHeader.ipv6.dst_mac_addr = null_mac;
			udpHeader.ipv6.src_ipv6_addr = addr;
			udpHeader.sourcePort = 80;
			udpHeader.destPort = 80;
			net_udp_send(&udpHeader, "Test", 4);
		}

		if (enc_idle && !gotChar) {
			__bis_SR_register(CPUOFF | GIE);
		}
	}
}

void __attribute__((interrupt PORT1_VECTOR))
PORT1_ISR(void) {
	if (P1IFG & ENC_INT) {
		enc_handle_int();
		__bic_SR_register_on_exit(CPUOFF);
	}

	P1IFG = 0;
}
