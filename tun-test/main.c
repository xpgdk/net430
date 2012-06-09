#include "stack.h"
#include "tcp.h"
#include "mem.h"

#include <stdio.h>

void server_socket_callback(int socket, uint8_t state, uint16_t count, DATA_CB dataCb, void *priv) {
	if( state == TCP_STATE_ESTABLISHED && count > 0 ) {
		uint8_t buf[count];
		dataCb(buf, count, priv);
		printf("Got %d bytes\n", count);
		tcp_send(socket, buf, count);
	} else if( state == TCP_STATE_CLOSED) {
		printf("Connection closed\n");
		tcp_listen(socket, 8000);
	}
}

int
main(int argc, char *argv[]) {
	uint8_t maca[] = {0xea,0x75,0xbf,0x72,0x0f,0x3d};

	mem_init();
	net_init(maca);

	int server_socket = tcp_socket(server_socket_callback, 500);
	tcp_listen(server_socket, 8000);

	net_main();
}
