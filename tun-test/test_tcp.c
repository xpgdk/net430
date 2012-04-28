#ifdef HAVE_TCP

#include "test.h"

#include "tcp.h"
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

static bool test_tcp_compare_trivial(void);
static bool test_tcp_compare_overflow(void);
static bool test_tcp_in_window(void);

void
test_tcp_main(void) {
	RUN_TEST(test_tcp_compare_trivial);
	RUN_TEST(test_tcp_compare_overflow);
	RUN_TEST(test_tcp_in_window);
}

static bool
test_tcp_compare_trivial(void) {
	uint32_t x, y;

	x = y = 0xfff;
	ASSERT("Equals", tcp_compare(&x,&y) == 0);
	
	x = 0;
	y = 1000;
	ASSERT("Greater", tcp_compare(&x,&y) < 0);

	x = 1000;
	y = 10;
	ASSERT("Smaller", tcp_compare(&x,&y) > 0);

	return true;
}

static bool
test_tcp_compare_overflow(void) {
	uint32_t x, y;

	x = y = -1; // 2**32 - 1
	x += 10;
	ASSERT("Greater direct", x < y);
	ASSERT("Greater", tcp_compare(&x,&y) > 0);

	x = y = -1; // 2**32 - 1
	y++;
	ASSERT("Smaller", tcp_compare(&x,&y) < 0);
	ASSERT("Smaller direct", x > y);

	return true;
}

static bool
test_tcp_in_window(void) {
	uint32_t no, min, max;

	min = 100;
	max = 5000;
	no = 500;
	ASSERT("100 <= 500 <= 5000", tcp_in_window(&no, &min, &max));

	min = 100;
	max = 5000;
	no = 50;
	ASSERT("!(100 <= 50 <= 5000)", !tcp_in_window(&no, &min, &max));

	min = 100;
	max = 5000;
	no = 10000;
	ASSERT("!(100 <= 10000 <= 5000)", !tcp_in_window(&no, &min, &max));

	min = -6;
	max = 100;
	no = 0;
	ASSERT("2**32-5 <= 0 <= 100", tcp_in_window(&no, &min, &max));

	min = -6;
	max = 100;
	no = -1;
	ASSERT("2**32-5 <= 2**32-1 <= 100", tcp_in_window(&no, &min, &max));

	min = -6;
	max = 100;
	no = 50;
	ASSERT("2**32-5 <= 50 <= 100", tcp_in_window(&no, &min, &max));

	min = -6;
	max = 100;
	no = 500;
	ASSERT("1(2**32-5 <= 500 <= 100)", !tcp_in_window(&no, &min, &max));

	return true;
}

#endif
