#ifndef _TUN_H
#define _TUN_H

extern int fd;
extern uint16_t deferred_id;

struct data_prov_priv {
	uint8_t *data;
	uint16_t count;
};

uint16_t
data_provider(uint8_t *buf, uint16_t count, void *priv);
#endif
