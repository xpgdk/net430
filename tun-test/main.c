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

	deferred_id = mem_alloc(1500);

	printf("Deferred ID: %d\n", deferred_id);
	printf("MEM FREE: %d\n", mem_free());

	struct pollfd p[1];
	p[0].fd = fd;
	p[0].events = POLLIN;

	int server_socket = tcp_socket(server_socket_callback);
	tcp_listen(server_socket, 8000);

	while(1) {
		int nread;
		struct etherframe frame;

		nread = poll(p, 1, 500);

		if (nread == 0) {
			net_tick();
			continue;
		}
		nread = read(fd, &frame, sizeof(frame));
		if(nread < 0) {
			perror("Reading from interface");
			close(fd);
			exit(1);
		}

		struct data_prov_priv p;
		p.data = frame.payload;
		p.count = nread - sizeof(struct etherheader);
		handle_ethernet(&frame.header, p.count, data_provider, &p);
		
	}
}
