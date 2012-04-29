IP430_DIR=../ip430
IP430_A=$(IP430_DIR)/ip430.a
CFLAGS=-std=gnu99 -g -O0 -DHAVE_TCP -I$(IP430_DIR) -DUDP_LOG
OBJS=tun.o mem_file.o debug.o main.o
TEST_OBJS=test_tcp.o test_main.o mem_file.o debug.o tun.o test_stack.o

tun: $(IP430_A) $(OBJS)
	$(CC) -lm -o $@ $(OBJS) $(IP430_A)

test: $(IP430_A) $(TEST_OBJS)
	$(CC) -o $@ $(TEST_OBJS) $(IP430_A)

$(IP430_A): force
	$(MAKE) INCLUDE_PATH=-I$(PWD) -C $(IP430_DIR)

.c.o :
	$(CC) $(CFLAGS) -c $<

force:
	

clean:
	$(MAKE) -C $(IP430_DIR) clean
	rm -f *.o tun
