IP430_OBJS=stack.o \
     tcp.o \
     udp.o \
     icmp.o \
     logger_udp.o

IP430_DEPS=$(patsubst %,$(IP430_DIR)/%,$(IP430_OBJS))
