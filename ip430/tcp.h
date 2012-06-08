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
#define TCP_STATE_SYN_RECEIVED 		4
#define TCP_STATE_ESTABLISHED		5
#define TCP_STATE_CLOSE_WAIT		6
#define TCP_STATE_LAST_ACK		7
#define TCP_STATE_FIN_WAIT_1		8
#define TCP_STATE_FIN_WAIT_2		9
#define TCP_STATE_TIME_WAIT		10

#define TCP_MSL				2*60 // 2 minutes

typedef void (*tcp_callback)(int,  uint8_t, uint16_t, DATA_CB , void *);

struct tcb {
	uint8_t		local_addr[16];
	uint8_t  	remote_addr[16];
	uint16_t 	tcp_local_port;
	uint16_t 	tcp_remote_port;

	uint32_t 	tcp_snd_una;
	uint32_t 	tcp_snd_nxt;
	//uint32_t tcp_snd_wnd;
	//uint32_t tcp_iss;

	uint32_t 	tcp_rcv_nxt;
	//uint32_t tcp_rcv_wnd;
	//uint32_t tcp_irs;
	uint8_t		tcp_state;

	uint16_t	tcp_timeout;

	tcp_callback	callback;
	uint16_t	retransmit_id;
	uint16_t	retransmit_size;
	uint16_t	retransmit_used;
	bool		has_retransmit;
	uint16_t	retransmit_flags;
	uint16_t	retransmit_time;
};

extern uint32_t tcp_initialSeqNo;

/* Internal functions */
void handle_tcp(uint8_t *macSource, uint8_t *sourceAddr, uint8_t *destIPAddr, uint16_t length, DATA_CB dataCb, void *priv);
void tcp_init(void);
void tcp_send_packet(struct tcb *tcb, uint16_t flags);
void net_tcp_end_packet(struct tcb *tcb);
bool tcp_in_window(uint32_t *no, uint32_t *min, uint32_t *max);
int8_t tcp_compare(uint32_t *no1, uint32_t *no2);
void tcp_timeout(uint16_t timeValue);
void tcp_add_retransmit(struct tcb *tcb, const char *buf, uint16_t len);
void tcp_retransmit(struct tcb *tcb);

/* TCP API */
int tcp_socket(tcp_callback callback, uint16_t retransmit_size);
void tcp_connect(int socket, uint8_t *local_addr, uint8_t *remote_addr, uint16_t port);

void tcp_listen(int socket, uint16_t port);
bool tcp_send(int socket, const uint8_t *buf, uint16_t count);
void tcp_close(int socket);

bool tcp_send_start(int socket);
void tcp_send_data(int socket, const uint8_t *buf, uint16_t count);
void tcp_send_end();

#endif
