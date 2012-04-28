#ifndef _TEST_H
#define _TEST_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define RUN_TEST(testFunc) do {if(testFunc()) {printf( #testFunc ": Success\n");} else {printf( #testFunc ": Fail\n");}} while(0)

#define ASSERT(msg,exp) do {if(!(exp)) {printf( #msg ": Fail\n"); return false;} } while(0)

#endif
