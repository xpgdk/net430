#ifndef TCP_H
#define TCP_H

#include "stack.h"

#define TCP_FIN		(1<<0)
#define TCP_SYN		(1<<1)
#define TCP_RST		(1<<2)
#define TCP_PSH		(1<<3)
#define TCP_ACK		(1<<4)
#define TCP_URG		(1<<5)

void handle_tcp(uint8_t *macSource, uint8_t *sourceAddr, uint8_t *destIPAddr, uint16_t length, DATA_CB dataCb, void *priv);
void tcp_init(void);

#endif
