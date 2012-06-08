#include <msp430.h>
#include <net430.h>
#include <stdbool.h>
#include <string.h>

#include <tcp.h>
#include <mem.h>
#include "temp_sensor.h"

const uint8_t mac_addr[] = { 0x00, 0xC0, 0x033, 0x50, 0x48, 0x10 };

const static char httpResponseHeader[] = "HTTP/1.1 200 OK\r\n"
                "Server: net430\r\n"
                "Content-Type: application/json\r\n\r\n"
                "{'time': $NET_TIME$,"
                " 'temperature': $TEMP$,"
                " 'requestPath': '$REQUEST$'"
                "}";

enum HttpState {
  CLOSED = 0,
  IDLE,
  GOT_REQUEST,
  GOT_PARTIAL_REQUEST
};

static enum HttpState   httpState = CLOSED;
static int              responseBufferId;
static uint16_t         temperature;
static uint16_t         last_measurement = -1;
static char             requestPath[10];

void tcp_send_int(int socket, uint16_t i) {
  uint8_t buf[7] = { ' ', ' ', ' ', ' ', ' ', ' ', ' ' };
  uint8_t count;

  itoa(i, buf, 10);

  // Count valid chars
  for(count=0; buf[count] >= 48 && buf[count] <= 57; count++);

  tcp_send_data(socket, buf, count);
}

void tcp_send_template_data(int socket, const char *buf, uint16_t count) {
  const char *end = buf + count;
  while (buf < end) {
    const char *p = strchr(buf, '$');
    // Copy data up to p
    if (p == NULL) {
      p = end;
    }

    tcp_send_data(socket, buf, p - buf);
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
          tcp_send_int(socket, net_get_time());
        } else if (strncmp(buf, "TEMP", 4) == 0) {
          tcp_send_int(socket, temperature/1364);
          tcp_send_data(socket, ".", 1);
          tcp_send_int(socket, (temperature%1364)/136);
        } else if (strncmp(buf, "REQUEST", 7) == 0) {
          tcp_send_data(socket, requestPath, strlen(requestPath));
        }
        e++;
      }
      buf = e;
    }
  }
}

void server_callback(int socket, uint8_t new_state, uint16_t count, DATA_CB data, void *priv) {
  if( count > 0 && httpState == IDLE) {
    uint8_t buf[10];
    uint16_t s;

    // First bytes are request
    s = data(buf, 4, priv);
    if( strncmp(buf, "GET", 3) == 0 ) {
      debug_puts("GET request");
      debug_nl();
      httpState = GOT_REQUEST;

      // Get path, we only support 10 bytes of path.
      // If we don't get the separating whitespace in there, we simply ignore the rest
      s = data(requestPath, 10, priv);
      char *sep = strchr(requestPath, ' ');
      if (sep != NULL) {
        *sep = '\0';
      } else {
        requestPath[10] = '\0';
      }
      debug_puts(requestPath);
      debug_nl();
    } else {
      debug_puts("Unknown request: ");
      debug_puts(buf);
      debug_nl();
    }
  }

  if( new_state == TCP_STATE_CLOSED ) {
    httpState = CLOSED;
  }
}

int main(void) {
  net430_init(mac_addr);

  responseBufferId = mem_alloc(20);

  int server_sock = tcp_socket(server_callback, 500);

  temp_sensor_init();

  while (true) {
    net430_tick();

    if (httpState == CLOSED) {
      tcp_listen(server_sock, 80);
      httpState = IDLE;
    } else if( httpState == GOT_REQUEST ) {
      tcp_send_start(server_sock);
      tcp_send_template_data(server_sock, httpResponseHeader, sizeof(httpResponseHeader)-1);
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
