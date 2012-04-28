#include "mem.h"
#include "spi_mem.h"

#define SPI_MEM_SIZE	0x8000
static uint16_t			mem_current;

uint16_t mem_alloc(uint16_t size) {
	uint16_t id = mem_current;
	spi_mem_zero(id, size);
	mem_current += size;
	return id;
}

uint16_t mem_free(void){
	return SPI_MEM_SIZE - mem_current;
}

uint16_t mem_read(uint16_t id, uint16_t offset, void *buf, uint16_t count) {
	spi_mem_read(id+offset, buf, count);
#if 0
	debug_puts("Read from ");
	debug_puthex(id+offset);
	debug_nl();
	print_buf(buf, count);
	debug_nl();
#endif

	return count;
}

uint16_t mem_write(uint16_t id, uint16_t offset, const void *buf, uint16_t count) {
#if 0
	debug_puts("Writing to ");
	debug_puthex(id+offset);
	debug_nl();
	print_buf(buf, count);
	debug_nl();
#endif
	spi_mem_write(id+offset, buf, count);
	return count;
}

void mem_init(void) {
	mem_current = 0;
}
