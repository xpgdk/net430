#include <msp430.h>
#include <net430.h>
#include <stdbool.h>
#include <string.h>

#include <tcp.h>
#include <mem.h>
#include "temp_sensor.h"

const uint8_t mac_addr[] = { 0xea, 0x75, 0xbf, 0x72, 0x0f, 0x3d };

const static char httpResponseHeader[] = "HTTP/1.1 200 OK\r\n"
                "Server: net430\r\n"
                "Content-Type: application/json\r\n\r\n"
                "{'time': $NET_TIME$,"
                " 'temperature': $TEMP$"
                "}";

enum HttpState {
  CLOSED = 0,
  IDLE,
  GOT_REQUEST,
  GOT_PARTIAL_REQUEST
};

static enum HttpState   httpState = IDLE;
static int              responseBufferId;
static uint16_t         temperature;
static uint16_t         last_measurement = -1;

void tcp_send_int(uint16_t i) {
  uint8_t buf[5] = { ' ', ' ', ' ', ' ', ' ' };
  uint8_t count;

  itoa(i, buf, 10);

  // Count valid chars
  for(count=0; buf[count] >= 48 && buf[count] <= 57; count++);

  tcp_send_data(buf, count);
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
        if (strncmp(buf, "NET_TIME", 8) == 0) {
          tcp_send_int(net_get_time());
        } else if (strncmp(buf, "TEMP", 4) == 0) {
          tcp_send_int(temperature/1364);
          tcp_send_data(".", 1);
          tcp_send_int((temperature%1364)/136);
        }
        e++;
      }
      buf = e;
    }
  }
}

void server_callback(int socket, uint8_t new_state, uint16_t count, DATA_CB data, void *priv) {
  if( count > 0 ) {
    uint8_t buf[10];
    uint16_t s;
    s = data(buf, 10, priv);
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

  temp_sensor_init();

  while (true) {
    net430_tick();

    if (httpState == CLOSED) {
      tcp_listen(server_sock, 80);
    } else if( httpState == GOT_REQUEST ) {
      tcp_send_start(server_sock);
      tcp_send_template_data(httpResponseHeader, sizeof(httpResponseHeader)-1);
      tcp_send_end(server_sock);
      tcp_close(server_sock);
    }

    if ( net_get_time() != last_measurement ) {
      last_measurement = net_get_time();
      temp_sensor_read(INCH_10);
    } else {
      temp_sensor_read_result(&temperature);
      temperature = -40826 + 564*(temperature-600);
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
