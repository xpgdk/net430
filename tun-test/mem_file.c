#include "mem.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static int mem_fd;
uint16_t mem_freeptr;

void
mem_init(void)
{
	mem_fd = open("secondary-memory-file", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
}

uint16_t
mem_alloc(uint16_t size)
{
	uint16_t p = mem_freeptr;
	mem_freeptr += size;
	return p;
}

uint16_t
mem_free(void)
{
	return 65535 - mem_freeptr;
}

uint16_t
mem_read(uint16_t id, uint16_t offset, uint8_t *buf, uint16_t count)
{
	lseek(mem_fd, id+offset, SEEK_SET);
	return read(mem_fd, buf, count);
}

uint16_t
mem_write(uint16_t id, uint16_t offset, const uint8_t *buf, uint16_t count)
{
	lseek(mem_fd, id+offset, SEEK_SET);
	return write(mem_fd, buf, count);
}
