.global delayMs
.text

#include "config.h"
#if 1
/* If the inner-loop runs for 65535 x 3 cycles = 196605 cycles.
   At 1MHz this takes 196605/1MHz = 196ms.
   At 16MHz this takes 196605/16MHz = 12.28 ms.

   We want the inner-loop to run for as close to 1ms as possible.
   CYCLES = 1ms * CPU_FREQ.
   We subtract the overhead involved in controlling the inner-loop (2+1+2).
   The additional overhead for the return is not compensated, but is at most 1ms (@1MHz).
   Minimum delay by this function is 2ms @ 1MHz (when 1ms is given as argument).
*/
delayMs:
			mov #((FCPU/1000)-6)/3, r14		//	[2]
delayMs_inner:
			dec r14						//	[1]
			jne delayMs_inner			//	[2]
			dec r15						//	[1]
			jne delayMs					//	[2]
			ret							//	[3]

            .end

#endif
