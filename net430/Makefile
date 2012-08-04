PROG=no-app
IP430_DIR=../ip430
IP430_A=$(IP430_DIR)/ip430.a
MCU=-mmcu=msp430g2553
CFLAGS=$(MCU) -std=gnu99 -Os
COMPILER_FLAGS=$(CFLAGS) -I$(PWD) -I$(IP430_DIR)
OBJS=enc28j60.o  mem.o  spi.o  spi_mem.o  uart.o cpu_asm.o net430.o
CC=msp430-gcc
AR=msp430-ar

net430.a: $(IP430_A) $(OBJS)
	$(AR) r $@ $(OBJS) $(IP430_A)

$(IP430_A): force
	$(MAKE) CC=$(CC) AR=$(AR) -C $(IP430_DIR) CFLAGS="$(COMPILER_FLAGS)"

.c.o :
	$(CC) $(COMPILER_FLAGS) -c $<

.S.o :
	$(CC) $(CFLAGS) -c $<

force:
	

clean:
	$(MAKE) -C $(IP430_DIR) clean
	rm -f *.o net430.a
