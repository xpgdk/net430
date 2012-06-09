#NET430_DIR=../net430
IP430_DIR=../ip430
include $(IP430_DIR)/ip430.mk

PROG=tun-test
CFLAGS=-std=gnu99 -Os -I$(PWD) -I$(IP430_DIR) -DHAVE_TCP -DDEBUG_TCP -DSTDOUT_LOG
OBJS=debug.o \
	mem_file.o \
	test_tcp.o \
	main.o \
	stack-main.o \
	test_stack.o \
	tun.o

CC=gcc
AR=ar

$(PROG).elf: $(IP430_DEPS) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(IP430_OBJS)

.c.o :
	$(CC) $(CFLAGS) -c $<

.S.o :
	$(CC) $(CFLAGS) -c $<

force:
	
clean:
	rm -f *.o $(PROG).elf
