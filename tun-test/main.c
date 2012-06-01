#include <net/if.h>

#include <linux/if_tun.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <poll.h>
#include <stdbool.h>

#include "stack.h"
#include "mem.h"
#include "tcp.h"
#include "tun.h"
#include "logger_udp.h"

int tun_alloc(char *dev, int flags) {

	struct ifreq ifr;
	int fd, err;
	char *clonedev = "/dev/net/tun";

	/* Arguments taken by the function:
	 *
	 * char *dev: the name of an interface (or '\0'). MUST have enough
	 *   space to hold the interface name if '\0' is passed
	 * int flags: interface flags (eg, IFF_TUN etc.)
	 */

	/* open the clone device */
	if( (fd = open(clonedev, O_RDWR)) < 0 ) {
		return fd;
	}

	/* preparation of the struct ifr, of type "struct ifreq" */
	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;   /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

	if (*dev) {
		/* if a device name was specified, put it in the structure; otherwise,
		 * the kernel will try to allocate the "next" device of the
		 * specified type */
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	/* try to create the device */
	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
		close(fd);
		return err;
	}

	/* if the operation was successful, write back the name of the
	 * interface to the variable "dev", so the caller can know
	 * it. Note that the caller MUST reserve space in *dev (see calling
	 * code below) */
	strcpy(dev, ifr.ifr_name);

	/* this is the special file descriptor that the caller will use to talk
	 * with the virtual interface */
	return fd;
}

const static uint8_t dst[] = {0x20, 0x01, 0x16, 0xd8, 0xdd, 0xaa, 0x00, 0x1,
	0x02, 0x23, 0x54, 0xff, 0xfe, 0xd5, 0x46, 0xf0};

void server_socket_callback(int socket, uint8_t state, uint16_t count, DATA_CB dataCb, void *priv) {
	if( state == TCP_STATE_ESTABLISHED && count > 0 ) {
		uint8_t buf[count];
		dataCb(buf, count, priv);
		print_buf(buf, count);
		debug_nl();
		printf("Got %d bytes\n", count);
		tcp_send(socket, buf, count);
	} else if( state == TCP_STATE_CLOSED) {
		tcp_listen(socket, 8000);
	}
}
const static char httpRequest[] = "GET /post-notify.php HTTP/1.0\r\n"
//"Host: script.xpg.dk\r\n\r\n";
"Host: localhost\r\n\r\n";

void client_socket_callback(int client_socket, uint8_t new_state, uint16_t count,
		DATA_CB data, void *priv) {
	debug_puts("Client state: ");
	debug_puthex(new_state);
	debug_nl();

	if (new_state == TCP_STATE_ESTABLISHED && count == 0) {
		tcp_send(client_socket, httpRequest, sizeof(httpRequest) - 1);
		tcp_close(client_socket);
	}
}

uint16_t
net_get_time(void) {
	return time(NULL) & 0xFFFF;
}


void strreverse(char* begin, char* end) {

	char aux;

	while(end>begin)

		aux=*end, *end--=*begin, *begin++=aux;

}

void itoa(int value, char* str, int base) {

	static char num[] = "0123456789abcdefghijklmnopqrstuvwxyz";

	char* wstr=str;

	int sign;

	div_t res;



	// Validate base

	if (base<2 || base>35){ *wstr='\0'; return; }



	// Take care of sign

	if ((sign=value) < 0) value = -value;



	// Conversion. Number is reversed.

	do {

		res = div(value,base);

		*wstr++ = num[res.rem];

	}while(value=res.quot);

	if(sign<0) *wstr++='-';

	*wstr='\0';



	// Reverse string

	strreverse(str,wstr-1);

}

int
main(int argc, char *argv[]) {
	char tun_name[IFNAMSIZ];

	strcpy(tun_name, "tap0");

	fd = tun_alloc(tun_name, IFF_TAP | IFF_NO_PI);

	if( fd < 0) {
		perror("Allocating interface");
		exit(1);
	}

	uint8_t maca[] = {0xea,0x75,0xbf,0x72,0x0f,0x3d};
	mem_init();
	net_init(maca);

#ifdef UDP_LOG
	logger_udp_init();
#endif

	deferred_id = mem_alloc(1500);

	printf("Deferred ID: %d\n", deferred_id);
	printf("MEM FREE: %d\n", mem_free());

	struct pollfd p[2];
	p[0].fd = fd;
	p[0].events = POLLIN;
	p[1].fd = 0;
	p[1].events = POLLIN;

	int server_socket = tcp_socket(server_socket_callback);
	tcp_listen(server_socket, 8000);

	int client_socket = tcp_socket(client_socket_callback);

	while(1) {
		int nread;
		struct etherframe frame;

		nread = poll(p, 2, 500);

		if (nread == 0) {
			net_tick();
			continue;
		}
		if(p[1].revents != 0) {
			uint8_t addr[16];
			debug_puts("Button pressed");
			debug_nl();
			net_get_address(ADDRESS_STORE_MAIN_OFFSET, addr);
			tcp_connect(client_socket, addr, dst, 80);
			read(0, &frame, 1);
		}

		if(p[0].revents != 0 ) {
			nread = read(fd, &frame, sizeof(frame));
			if(nread < 0) {
				close(fd);
				exit(1);
			}

			struct data_prov_priv p;
			p.data = frame.payload;
			p.count = nread - sizeof(struct etherheader);
			handle_ethernet(&frame.header, p.count, data_provider, &p);
		} 		
	}
}
