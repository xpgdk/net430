IP430_DIR=../ip430
IP430_A=$(IP430_DIR)/ip430.a
CFLAGS=-std=gnu99 -g -O0 -DHAVE_TCP -I$(IP430_DIR)
OBJS=tun.o mem_file.o debug.o

tun: $(IP430_A) $(OBJS)
	$(CC) -o $@ $(OBJS) $(IP430_A)

$(IP430_A): force
	$(MAKE) -C $(IP430_DIR)

.c.o :
	$(CC) $(CFLAGS) -c $<

force:
	

clean:
	rm -f *.o tun
