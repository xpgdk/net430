#include <msp430.h>
#include <net430.h>
#include <stdbool.h>
#include "tcp.h"
#include "mem.h"

const uint8_t mac_addr[] = { 0xea, 0x75, 0xbf, 0x72, 0x0f, 0x3d };

const static char httpResponseHeader[] = "HTTP/1.1 200 OK\r\n"
                "Server: net430\r\n"
                "Content-Type: application/json\r\n\r\n"
                "{'name': 'value'}";

enum HttpState {
  CLOSED = 0,
  IDLE = 1,
  GOT_REQUEST,
};

static enum HttpState httpState = IDLE;
static int responseBufferId;

void server_callback(int socket, uint8_t new_state, uint16_t count, DATA_CB data, void *priv) {
  if( count > 0 ) {
    // Handle incoming data, currently, we do nothing and assume an HTTP request :-)
    httpState = GOT_REQUEST;
  }

  if( new_state == TCP_STATE_CLOSED ) {
    httpState = CLOSED;
  }
}

int main(void) {
  net430_init(mac_addr);

  responseBufferId = mem_alloc(20);

  int server_sock = tcp_socket(server_callback);
  tcp_listen(server_sock, 80);

  while (true) {
    net430_tick();

    if( httpState == CLOSED ) {
      tcp_listen(server_sock, 80);
    } else if( httpState == GOT_REQUEST ) {
      tcp_send_start(server_sock);
      tcp_send_data(httpResponseHeader, sizeof(httpResponseHeader)-1);
      tcp_send_end(server_sock);
      tcp_close(server_sock);
    }

    if (enc_idle ) {
      __bis_SR_register(CPUOFF | GIE);
    }
  }
  return 0;
}

void __attribute__((interrupt PORT1_VECTOR))
  PORT1_ISR(void) {
    if (P1IFG & ENC_INT) {
      enc_handle_int();
      __bic_SR_register_on_exit(CPUOFF);
    }
    P1IFG = 0;
  }
