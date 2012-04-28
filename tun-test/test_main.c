#include "test_tcp.h"
#include "test_stack.h"

int
main(int argc, char *argv[]) {
	test_stack_main();
#ifdef HAVE_TCP
	test_tcp_main();
#endif
}
