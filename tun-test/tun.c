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

uint16_t deferred_id;

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


struct data_prov_priv {
	uint8_t *data;
	uint16_t count;
};

uint16_t
data_provider(uint8_t *buf, uint16_t count, void *priv)
{
	struct data_prov_priv *p = (struct data_prov_priv*)priv;
	uint16_t c = count;

	if (p->count < c)
		c = p->count;

	memcpy(buf, p->data, c);

	p->count -= c;
	p->data += c;

	return c;
}

int fd;


void server_socket_callback(int socket, uint8_t state, uint16_t count, DATA_CB dataCb, void *priv) {
	if( state == TCP_STATE_ESTABLISHED && count > 0 ) {
		uint8_t buf[count];
		dataCb(buf, count, priv);
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

static uint8_t xmit_buffer[1500];
static uint8_t xmit_offset;
static bool defer = false;
static bool got_deferred = false;
static uint16_t deferred_size = 0;
static uint16_t checksum_location;

/*
 Start sending a buffer to the link-layer.
 If the destination mac is null_mac, a positive ID will be returned,
 which must be used as argument in net_send_deferred() or net_drop_deferred().
 Negative value means that no more room is available and that the frame
 cannot be transmitted.
*/
int16_t
net_send_start(struct etherheader *header) {

	if (got_deferred) {
		return -1;
	}

	xmit_offset = sizeof(struct etherheader);
	checksum_location = 0;

	defer = true;

	for(int i=0; i<6; i++) {
		if( header->mac_dest[i] != 0) {
			defer = false;
			break;
		}
	}

	if (defer) {
		printf("Packet is being written to secondary store\n");
		mem_write(deferred_id, 0, (const uint8_t*)header, sizeof(struct etherheader));
		return deferred_id;
	} else {
		memcpy(xmit_buffer, header, sizeof(struct etherheader));
		return 0;
	}
}

void
net_send_data(const uint8_t *buf, uint16_t count) {
	if (defer) {
		mem_write(deferred_id, xmit_offset, buf, count);
	} else {
		memcpy(xmit_buffer+xmit_offset, buf, count);
	}
	xmit_offset += count;
}

void
net_send_dummy_checksum(void) {
	uint8_t null_buf[] = {0x00, 0x00};
	checksum_location = xmit_offset;
	net_send_data(null_buf, 2);
}

void
net_send_replace_checksum(uint16_t checksum) {
	uint8_t buf[2];

	if (checksum_location == 0) {
		return;
	}

	buf[0] = checksum >> 8;
	buf[1] = checksum & 0xFF;
	if (defer) {
		mem_write(deferred_id, checksum_location, buf, 2);
	} else {
		memcpy(xmit_buffer+checksum_location, buf, 2);
	}
}

uint16_t
net_get_length(void) {
	return xmit_offset;
}

void
net_send_at_offset(uint16_t offset, uint16_t val) {
	debug_puts("net_send_at_offset: ");
	debug_puthex(offset);
	debug_puts(", ");
	debug_puthex(val);
	debug_nl();
	uint8_t buf[2];
	buf[0] = val >> 8;
	buf[1] = val & 0xFF;
	if (defer) {
		mem_write(deferred_id, offset, buf, 2);
	} else {
		memcpy(xmit_buffer+offset, buf, 2);
	}
}

void
net_send_end() {
	if (defer) {
		printf("Packet deferred\n");
		deferred_size = xmit_offset;
	} else {
		write(fd, xmit_buffer, xmit_offset);
	}
}

void
net_send_deferred(int16_t id, uint8_t const *dstMac) {
	printf("Sending deferred\n");
	got_deferred = false;
	struct etherheader *header;
	header = (struct etherheader*)xmit_buffer;

	mem_read(id, 0, xmit_buffer, sizeof(struct etherheader));
	
	memcpy(header->mac_dest, dstMac, 6);

	mem_read(id, sizeof(struct etherheader), xmit_buffer+sizeof(struct etherheader), deferred_size-sizeof(struct etherheader));
	write(fd, xmit_buffer, deferred_size);
}

void
net_drop_deferred(int16_t id) {
	got_deferred = false;
}
