#include <msp430.h>
#include "uart.h"
#include "enc28j60.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "config.h"
#include "cpu.h"
#include "stack.h"
#include "spi.h"
#include "spi_mem.h"
#include "udp.h"
#include "tcp.h"

#include "rfm.h"

const uint8_t mac_addr[] = { 0xea, 0x75, 0xbf, 0x72, 0x0f, 0x3d };

static unsigned char gotChar = 0;
static bool gotData = false;
static bool closed = false;
static bool sendRequest = false;

void uart_rx_isr(unsigned char c) {
	gotChar = c;
}

void server_callback(int socket, uint8_t new_state, uint16_t count,
		DATA_CB data, void *priv) {
	debug_puts("State: ");
	debug_puthex(new_state);
	debug_nl();

	debug_puts("Data count: ");
	debug_puthex(count);
	debug_nl();

	if (count > 0) {
		gotData = true;
	}

	if (new_state == TCP_STATE_CLOSED) {
		closed = true;
	}
}

void client_callback(int socket, uint8_t new_state, uint16_t count,
		DATA_CB data, void *priv) {
	debug_puts("Client state: ");
	debug_puthex(new_state);
	debug_nl();

	if (new_state == TCP_STATE_ESTABLISHED && count == 0) {
		sendRequest = true;
	}
	if (new_state == TCP_STATE_CLOSED) {
		P2IE |= BIT1;
	}
}

#if 0
const static uint8_t dst[] = { 0x20, 0x01, 0x16, 0xd8, 0xdd, 0xaa, 0x00, 0x1,
		0x02, 0x23, 0x54, 0xff, 0xfe, 0xd5, 0x46, 0xf0 };
#endif

const static uint8_t dst[] = { 0x26, 0x07, 0xf2, 0x98, 0x00, 0x2, 0x01, 0x20,
		0x00, 0x00, 0x00, 0x00, 0x0d, 0x83, 0xc0, 0xdc };

const static char httpResponseHeader[] =
		"HTTP/1.1 200 OK\r\n"
				"Server: net430\r\n"
				"Content-Type: text/html\r\n\r\n<html><head><meta http-equiv=\"Refresh\" content=\"5\"></head><body>Usage counter</body></html>";
#define RESPONSE_HEADER_SIZE (sizeof(httpResponseHeader)-1)

const static char httpRequest[] = "GET /snail-notify.php HTTP/1.1\r\n"
		"Host: xpg.dk\r\n\r\n";

static bool sendSignal = false;

uint16_t requestCounter = 0;

#define PACKET_BAT_LEVEL 	0xF1
#define PACKET_ACK			0xF2
#define PACKET_SIGNAL		0xF3

int main(void) {
	cpu_init();

	uart_init();

	unsigned char c;
//	uart_getc(&c);

	delayMs(500);

	P2DIR &= ~BIT1;
	P2REN |= BIT1;
	P2OUT |= BIT1;
	P2IES |= BIT1;
	P2IFG = 0;
	P2IE |= BIT1;

	// register ISR called when data was received
	uart_set_rx_isr_ptr(uart_rx_isr);

	__bis_SR_register(GIE);

	spi_init();

	/* Initialize RFM-module */
	rf12_initialize(2, RF12_433MHZ, 33);

	spi_mem_init();

	enc_init(mac_addr);
	net_init(mac_addr);

	int client_socket = tcp_socket(client_callback);

	int server_sock = tcp_socket(server_callback);
	tcp_listen(server_sock, 8000);

	debug_puts("server_sock: ");
	debug_puthex(server_sock);
	debug_nl();

	while (true) {
		if (rf12_recvDone() && rf12_crc == 0) {
			if (rf12_data[0] == PACKET_BAT_LEVEL) {
				sendSignal = true;
			}
		}

		if (gotChar) {
			gotChar = 0;
			sendSignal = true;
		}


		net_tick();
		if (!enc_idle) {
			enc_action();
		}

		if (gotData) {
			gotData = false;

			uint8_t buf[5];
			uint16_t contentlength;

			contentlength = 17;

			itoa(contentlength, buf, 10);

			tcp_send(server_sock, httpResponseHeader, RESPONSE_HEADER_SIZE);
#if 0
			tcp_send_start(server_sock,
					RESPONSE_HEADER_SIZE + 4 + 17);
			tcp_send_data(httpResponseHeader, RESPONSE_HEADER_SIZE);
			tcp_send_data("\r\n\r\n", 4);
			tcp_send_data("Request Counter: ", 17);
			tcp_send_end();
#endif

			tcp_close(server_sock);
			gotData = false;
		}

		if (closed) {
			tcp_listen(server_sock, 8000);
			closed = false;
		}

		if (sendRequest) {
			sendRequest = false;
			tcp_send(client_socket, httpRequest, sizeof(httpRequest) - 1);
			tcp_close(client_socket);
		}
#if 1
		if (sendSignal) {
			uint8_t addr[16];
			debug_puts("Button pressed");
			debug_nl();
			net_get_address(ADDRESS_STORE_MAIN_OFFSET, addr);
			tcp_connect(client_socket, addr, dst, 80);
			sendSignal = false;
			/*
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
			 net_udp_send(&udpHeader, "Test", 4);*/
		}
#endif

		if (enc_idle && !gotChar  && rxstate == TXRECV ) {
			__bis_SR_register(CPUOFF | GIE);
		}
	}
}

void __attribute__((interrupt PORT1_VECTOR))
PORT1_ISR(void) {
#if 1
	if (P1IFG & ENC_INT) {
		enc_handle_int();
		__bic_SR_register_on_exit(CPUOFF);
	}
#endif
	P1IFG = 0;
}

void __attribute__((interrupt PORT2_VECTOR))
PORT2_ISR(void) {
	if (P2IFG & BIT1) {
		sendSignal = true;
		P2IE &= ~BIT1;
		__bic_SR_register_on_exit(CPUOFF);
	}
	if (P2IFG & BIT5) {
		__bic_SR_register_on_exit(CPUOFF);
		rf12_interrupt();
	}

	P2IFG = 0;
}
