#ifndef _NET430_H
#define _NET430_H

#include <stack.h>
#include <enc28j60.h>

void net430_init(const uint8_t *mac_addr);
void net430_tick(void);

#endif
