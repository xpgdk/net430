include ../ip430/ip430.mk
NET430_OBJS=cpu_asm.o \
	    enc28j60.o \
	    net430.o \
	    spi.o \
	    spi_mem.o \
	    mem.o \
	    uart.o

NET430_DEPS=$(patsubst %,$(NET430_DIR)/%,$(NET430_OBJS))
