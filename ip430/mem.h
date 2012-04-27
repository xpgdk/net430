#ifndef MEM_H
#define MEM_H

#include <stdint.h>

/* Allocates a piece of secondary memory.
 * Note, that this cannot be freed. */
uint16_t mem_alloc(uint16_t size);

uint16_t mem_free(void);

uint16_t mem_read(uint16_t id, uint16_t offset, void *buf, uint16_t count);
uint16_t mem_write(uint16_t id, uint16_t offset, const void *buf, uint16_t count);

void mem_init(void);

#endif
