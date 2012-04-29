CFLAGS := $(INCLUDE_PATH) -std=gnu99 -g -O0 -DHAVE_TCP -DUDP_LOG
OBJS=stack.o tcp.o udp.o icmp.o logger_udp.o

ip430.a: $(OBJS)
	ar r $@ $(OBJS)

.c.o :
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o
