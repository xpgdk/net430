#ifndef TCP_H
#define TCP_H

#include "stack.h"

#define TCP_FIN		(1<<0)
#define TCP_SYN		(1<<1)
#define TCP_RST		(1<<2)
#define TCP_PSH		(1<<3)
#define TCP_ACK		(1<<4)
#define TCP_URG		(1<<5)

#define TCP_STATE_NONE			0
#define TCP_STATE_CLOSED		1
#define TCP_STATE_LISTEN		2
#define TCP_STATE_SYN_SENT		3
#define TCP_STATE_SYN_RECEIVED 	4
#define TCP_STATE_ESTABLISHED	5
#define TCP_STATE_CLOSE_WAIT	6
#define TCP_STATE_LAST_ACK		7

typedef void (*tcp_callback)(int,  uint8_t, uint16_t, DATA_CB , void *);


struct tcb {
	uint8_t	 local_addr[16];
	uint8_t  remote_addr[16];
	uint16_t tcp_local_port;
	uint16_t tcp_remote_port;

	uint32_t tcp_snd_una;
	uint32_t tcp_snd_nxt;
	uint32_t tcp_snd_wnd;
	uint32_t tcp_iss;

	uint32_t tcp_rcv_nxt;
	uint32_t tcp_rcv_wnd;
	uint32_t tcp_irs;
	uint8_t	tcp_state;

	tcp_callback	callback;
};


/* Internal functions */
void handle_tcp(uint8_t *macSource, uint8_t *sourceAddr, uint8_t *destIPAddr, uint16_t length, DATA_CB dataCb, void *priv);
void tcp_init(void);
void tcp_send_packet(struct tcb *tcb, uint16_t flags, uint32_t count);
void net_tcp_end_packet(void);

/* TCP API */
int tcp_socket(tcp_callback callback);
void tcp_listen(int socket, uint16_t port);
void tcp_send(int socket, const uint8_t *buf, uint16_t count);

#endif
