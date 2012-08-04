#include <msp430.h>
#include <string.h>
#include "uart.h"
#include "debug.h"
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
#include "logger_udp.h"

const uint8_t mac_addr[] = { 0xea, 0x75, 0xbf, 0x72, 0x0f, 0x3d };

static unsigned char gotChar = 0;
static bool gotData = false;
static bool closed = false;
static bool sendRequest = false;
uint16_t timeValue = 0;

#define TIME_STEP	30 //seconds
void uart_rx_isr(unsigned char c) {
	gotChar = c;
}

void server_callback(int socket, uint8_t new_state, uint16_t count,
		DATA_CB data, void *priv) {
	CHECK_SP("server_callback: ");
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
	CHECK_SP("client_callback: ");
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
const static uint8_t dst[] = {0x20, 0x01, 0x16, 0xd8, 0xdd, 0xaa, 0x00, 0x1,
	0x02, 0x23, 0x54, 0xff, 0xfe, 0xd5, 0x46, 0xf0};
#else
//2607:F298:0002:0120:0000:0000:0243:A658
const static uint8_t dst[] = { 0x26, 0x07, 0xF2, 0x98, 0x00, 0x02, 0x01, 0x20,
		0x00, 0x00, 0x00, 0x00, 0x02, 0x43, 0xA6, 0x58 };
/*const static uint8_t dst[] = { 0x26, 0x07, 0xf2, 0x98, 0x00, 0x2, 0x01, 0x20,
 0x00, 0x00, 0x00, 0x00, 0x0d, 0x83, 0xc0, 0xdc };*/
#endif

const static char httpResponseHeader[] = "HTTP/1.1 200 OK\r\n"
		"Server: net430\r\n"
		"Content-Type: text/html\r\n\r\n"
		"<html><head><meta http-equiv=\"Refresh\" content=\"20\"></head>"
		"<body>"
		"Request counter: $USAGE_COUNTER$<br>"
		"Signal counter: $REQUEST_COUNTER$<br>"
		"Last battery level: $BATTERY_LEVEL$<br>"
		"</body></html>";

const static char httpRequest[] = "GET /post-notify.php HTTP/1.0\r\n"
		"Host: script.xpg.dk\r\n\r\n";
//"Host: localhost\r\n\r\n";

static bool sendSignal = false;

uint16_t requestCounter = 0;
uint16_t notificationCounter = 0;
uint16_t batLevel = 0;

#define PACKET_BAT_LEVEL 	0xF1
#define PACKET_ACK			0xF2
#define PACKET_SIGNAL		0xF3

bool getRandomBit() {
	ADC10CTL1 |= INCH_5;
	ADC10CTL0 |= SREF_1 + ADC10SHT_1 + REFON + ADC10ON;
	ADC10CTL0 |= ENC + ADC10SC;
	while (ADC10CTL1 & ADC10BUSY)
		;
	return ADC10MEM & 0x01;
}

void init_random() {
	uint16_t seqNo = 0;
	for (int i = 0; i < 16; i++) {
		seqNo |= getRandomBit() << i;
	}

	srand(seqNo);
}

void tcp_send_int(uint16_t i) {
	uint8_t buf[5] = { ' ', ' ', ' ', ' ', ' ' };

	itoa(i, buf, 10);

	tcp_send_data(buf, 4);
}

void tcp_send_template_data(const char *buf, uint16_t count) {
	const char *end = buf + count;
	while (buf < end) {
		const char *p = strchr(buf, '$');
		// Copy data up to p
		if (p == NULL) {
			p = end;
		}

		tcp_send_data(buf, p - buf);
		buf = p;

		if (p != end) {
			buf++;
			// Perform replacement
			const char *e = strchr(buf, '$');
			if (e == NULL) {
				e = end;
			} else {
				// Match is between buf and e
				if (strncmp(buf, "USAGE_COUNTER", 13) == 0) {
					tcp_send_int(requestCounter);
				} else if (strncmp(buf, "REQUEST_COUNTER", 15) == 0) {
					tcp_send_int(notificationCounter);
				} else if (strncmp(buf, "BATTERY_LEVEL", 13) == 0) {
					tcp_send_int(batLevel);
				}
				e++;
			}
			buf = e;
		}
	}
	debug_puts("Done");
	debug_nl();
}
uint16_t net_get_time(void) {
	return timeValue;
}
int main(void) {
	cpu_init();
	init_random();

	/* Select low-frequency mode */
	BCSCTL1 &= ~XTS;
	/* Set ACLK divider to 1 */
	BCSCTL1 |= DIVA_0;

	/* Select VLOCLK */
	BCSCTL3 &= ~(LFXT1S0 | LFXT1S1);
	BCSCTL3 |= LFXT1S_2;

	/* Initialize timer A0 */
	TA0CCTL0 = CM_0 | CCIE;
	TA0CTL = TASSEL_1 | ID_3 | MC_1 | TACLR;
	TA0CCR0 = (1500 * TIME_STEP);

#ifdef UART_ENABLE
	uart_init();

	// register ISR called when data was received
	uart_set_rx_isr_ptr(uart_rx_isr);
#endif

	unsigned char c;
//	uart_getc(&c);

	delayMs(1500);

	P2DIR &= ~BIT1;
	P2REN |= BIT1;
	P2OUT |= BIT1;
	P2IES |= BIT1;
	P2IFG = 0;
	P2IE |= BIT1;

	__bis_SR_register(GIE);

	spi_init();

	/* Initialize RFM-module */
	rf12_initialize(3, RF12_433MHZ, 33);

	spi_mem_init();

	enc_init(mac_addr);
	net_init(mac_addr);

#ifdef UDP_LOG
	logger_udp_init();
#endif

	int client_socket = tcp_socket(client_callback);

	int server_sock = tcp_socket(server_callback);
	tcp_listen(server_sock, 8000);

	debug_puts("server_sock: ");
	debug_puthex(server_sock);
	debug_nl();

	while (true) {

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
			requestCounter++;

			tcp_send_start(server_sock);

			tcp_send_template_data(httpResponseHeader,
					sizeof(httpResponseHeader) - 1);
#if 0

			tcp_send_data(httpResponseHeader, sizeof(httpResponseHeader)-1);
			tcp_send_data(buf, 4);
			tcp_send_data(httpResponseHeaderPart2, sizeof(httpResponseHeaderPart2)-1);
#endif
			tcp_send_end(server_sock);
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
		if (sendSignal) {
			uint8_t addr[16];
			debug_puts("Button pressed");
			debug_nl();
			notificationCounter++;
			net_get_address(ADDRESS_STORE_MAIN_OFFSET, addr);
			tcp_connect(client_socket, addr, dst, 80);
			sendSignal = false;
		}

#if 1
		if (rf12_recvDone()) {
			if (rf12_crc == 0) {
				debug_puts("Got RF12 packet: ");
				debug_puthex(rf12_data[0]);
				debug_nl();
				if (rf12_data[0] == PACKET_SIGNAL) {
					batLevel = rf12_data[1] << 8 | rf12_data[2];
					debug_puts("BAT LEVEL: ");
					debug_puthex(batLevel);
					//debug_puts(rf12_data + 1);
					debug_nl();
					sendSignal = true;
				} else if( rf12_data[0] == PACKET_BAT_LEVEL) {
					batLevel = rf12_data[1] << 8 | rf12_data[2];
				}
			}
		}
#endif

		if (enc_idle && !gotChar && rxstate == TXRECV) {
			__bis_SR_register(CPUOFF | GIE);
		}
	}
}

void __attribute__((interrupt TIMER0_A0_VECTOR))
TIMER0_A0_ISR(void) {
	__bic_SR_register_on_exit(CPUOFF);
	timeValue += TIME_STEP;
}

void __attribute__((interrupt PORT1_VECTOR))
PORT1_ISR(void) {
	if (P1IFG & ENC_INT) {
		enc_handle_int();
		__bic_SR_register_on_exit(CPUOFF);
	}
	P1IFG = 0;
}

void __attribute__((interrupt PORT2_VECTOR))
PORT2_ISR(void) {
	if (P2IFG & BIT5) {
		rf12_interrupt();
	}
	if (P2IFG & BIT1) {
		sendSignal = true;
		P2IE &= ~BIT1;
		__bic_SR_register_on_exit(CPUOFF);
	}
	P2IFG = 0;
}
