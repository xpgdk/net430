CFLAGS := $(INCLUDE_PATH) -std=gnu99 -g -Os
OBJS=stack.o tcp.o udp.o icmp.o logger_udp.o

ip430.a: $(OBJS)
	$(AR) r $@ $(OBJS)

.c.o :
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o ip430.a
