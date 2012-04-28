#include "stack.h"
#include "test.h"

static bool test_stack_checksum_odd(void);

void
test_stack_main(void) {
	RUN_TEST(test_stack_checksum_odd);
}

static bool
test_stack_checksum_odd(void) {
	uint8_t buf[] = {'H', 'E', 'L', 'L', 'O', 0x10};

	uint16_t val1, val2;

	checksum = 0;
	calc_checksum(buf, 4);
	val1 = checksum;

	checksum = 0;
	calc_checksum(buf, 3);
	calc_checksum(buf+3, 1);
	val2 = checksum;

	ASSERT("Check 1", val1 == val2);

	checksum = 0;
	calc_checksum(buf, 6);
	val1 = checksum;

	checksum = 0;
	calc_checksum(buf, 3);
	calc_checksum(buf+3, 3);
	val2 = checksum;
	ASSERT("Check 2", val1 == val2);

	checksum = 0;
	calc_checksum(buf, 1);
	calc_checksum(buf+1, 1);
	calc_checksum(buf+2, 2);
	calc_checksum(buf+4, 2);
	val2 = checksum;
	ASSERT("Check 3", val1 == val2);

	checksum = 0;
	calc_checksum(buf, 4);
	calc_checksum(buf+4, 2);
	val2 = checksum;
	ASSERT("Check 4", val1 == val2);
}
