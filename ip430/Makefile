CFLAGS=-std=gnu99 -g -O0 -DHAVE_TCP
OBJS=stack.o tcp.o udp.o

ip430.a: $(OBJS)
	ar r $@ $(OBJS)

.c.o :
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o
