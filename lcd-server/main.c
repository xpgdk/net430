#include <msp430.h>
#include <net430.h>
#include <stdbool.h>
#include <string.h>

#include <tcp.h>
#include <mem.h>
#include "temp_sensor.h"
#include "lcd.h"

const uint8_t mac_addr[] = { 0x00, 0xC0, 0x033, 0x50, 0x48, 0x12 };

const static char httpResponseHeader[] = "HTTP/1.1 200 OK\r\n"
                "Server: net430\r\n"
                "Content-Type: application/json\r\n\r\n"
                "{'time': $NET_TIME$,"
                " 'temperature': $TEMP$,"
                " 'requestPath': '$REQUEST$'"
                "}";

const static uint8_t CRLF_CRLF[] = {13,10,13,10};
const static uint8_t CONTENT_LENGTH[] = "Content-Length: ";

enum HttpState {
  CLOSED = 0,
  IDLE,
  RECEIVING_REQUEST,
  RECEIVING_HEADERS,
  RECEIVING_BODY,
  REQUEST_HANDLED,
  SEND_RESPONSE,
  FIN
};


static enum HttpState   httpState = CLOSED;
static uint16_t		temperature;
static uint16_t		last_measurement = -1;
//static char             requestPath[10];
static int		requestPathId;
static uint8_t		contentLength;

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
	  //tcp_send_data(socket, requestPath, strlen(requestPath));
	  tcp_send_data_from_mem(socket, requestPathId, 0, 10);
        }
        e++;
      }
      buf = e;
    }
  }
}

uint16_t read_to_mem(uint16_t id, uint16_t offset, uint16_t count, DATA_CB data, void *priv) {
  uint8_t buf[1];
  uint16_t s = count;
  uint16_t l = 0;

  while(count > 0 && s > 0) {
    s = data(buf, 1, priv);
    mem_write(id, offset, buf, s);
    offset += s;
    l+= s;
    count--;
  }
  return l;
}

void tcp_send_data_from_mem(int socket, uint16_t bufId, uint16_t offset, uint16_t count) {
  uint8_t buf[1];

  while(count > 0) {
    mem_read(bufId, offset, buf, 1);
    tcp_send_data(socket, buf, 1);
    count--;
    offset++;
  }
}

void lcd_putstring_from_mem(uint16_t bufId, uint16_t offset, uint16_t count) {
  uint8_t buf[1];

  while(count > 0) {
    mem_read(bufId, offset, buf, 1);
    lcd_putchar(buf[0]);
    count--;
    offset++;
  }
}

void server_callback(int socket, uint8_t new_state, uint16_t count, DATA_CB data, void *priv) {
  uint8_t buf[4];
  uint16_t s;
  uint8_t match = 0;

  debug_puts("server_callback, new_state: ");
  debug_puthex(new_state);
  debug_nl();
  if( new_state == TCP_STATE_ESTABLISHED && httpState == IDLE) {
    httpState = RECEIVING_REQUEST;
  }

  if( count > 0 && httpState == RECEIVING_REQUEST ) {
    // First bytes are request
    s = data(buf, 4, priv);
    if( strncmp(buf, "GET", 3) == 0 ||
	strncmp(buf, "POST", 4) == 0 ) {
      debug_puts("GET request");
      contentLength = 0;
      debug_nl();
      httpState = RECEIVING_HEADERS;
      match = 0;
      while( s > 0) {
	s = data(buf, 1, priv);
	if( buf[0] == CRLF_CRLF[match] ) {
	  match++;
	  debug_puts("Match: ");
	  debug_puthex(match);
	  debug_nl();
	} else {
	  match = 0;
	}

	if( match == 2) {
	  break;
	}
      }
    } else {
      debug_puts("Unknown request: ");
      debug_puts(buf);
      debug_nl();
      httpState = SEND_RESPONSE;
    }
  }

  if( count > 0 && httpState == RECEIVING_HEADERS) {
    uint8_t match_len = 0;
    /* Search for the two \13\10 (CRLF) in the request as that separates header from body */
    while(s > 0) {
      s = data(buf, 1, priv);
      if( buf[0] == CONTENT_LENGTH[match_len] ) {
	match_len++;
      } else if( match_len != sizeof(CONTENT_LENGTH)-1) {
	match_len = 0;
      } else if( match_len == sizeof(CONTENT_LENGTH)-1 &&
		 match < 2 &&
		 buf[0] != 13) {
	debug_puts("L: ");
	debug_puthex(buf[0]);
	debug_nl();
	contentLength = (contentLength*10) + (buf[0]-0x30);
      }

      if( buf[0] == CRLF_CRLF[match] ) {
	match++;
      } else {
	match = 0;
      }

      if( match == 1) {
	match_len = 0;
      }

      if( match == 4) {
	debug_puts("Got separator\n");
	httpState = RECEIVING_BODY;
	break;
      }
    }
  }

  if( count > 0 && httpState == RECEIVING_BODY) {
    debug_puts("Content Length: ");
    debug_puthex(contentLength);
    debug_nl();
    lcd_clear();
    while(s > 0 && contentLength > 0) {
      s = data(buf, 1, priv);
      lcd_putchar(buf[0]);
      debug_puthex(buf[0]);
      debug_nl();
      contentLength--;
    }

    if( contentLength == 0) {
      httpState = SEND_RESPONSE;
    }
  }

  if( new_state == TCP_STATE_CLOSED ) {
    httpState = CLOSED;
  }
}

int main(void) {
  net430_init(mac_addr);

  requestPathId = mem_alloc(100);

  int server_sock = tcp_socket(server_callback, 500);

  temp_sensor_init();

  debug_puts("main");
  debug_nl();

  lcd_init(16, 1);

  while (true) {
    net430_tick();

    if (httpState == CLOSED) {
      debug_puts("httpState == CLOSED");
      debug_nl();
      tcp_listen(server_sock, 80);
      httpState = IDLE;
    } else if( httpState == SEND_RESPONSE ) {
      debug_puts("httpState == SEND_RESPONSE");
      debug_nl();
      tcp_send_start(server_sock);
      tcp_send_template_data(server_sock, httpResponseHeader, sizeof(httpResponseHeader)-1);
      tcp_send_end(server_sock);
      tcp_close(server_sock);
      httpState = FIN;
    }

    if ( net_get_time() != last_measurement ) {
      debug_puts("new measurement");
      debug_nl();
      last_measurement = net_get_time();
      temp_sensor_read(INCH_10);
    } else if( temp_sensor_result_ready == true ) {
      debug_puts("reading measurement");
      debug_nl();
      temp_sensor_read_result(&temperature);
      temperature = -40826 + 564*(temperature-600);
    }

    if (enc_idle ) {
      /*debug_puts("enc_idle");
      debug_nl();*/
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
