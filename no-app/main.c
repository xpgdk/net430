#include <msp430.h>
#include <net430.h>

const uint8_t mac_addr[] = { 0xea, 0x75, 0xbf, 0x72, 0x0f, 0x3d };

int main(void) {
  net430_init(mac_addr);

  while (true) {
    net430_tick();
    if (enc_idle ) {
      __bis_SR_register(CPUOFF | GIE);
    }
  }
  return 0;
}

void __attribute__((interrupt PORT1_VECTOR))
PORT1_ISR(void) {
	if (P1IFG & ENC_INT) {
		enc_handle_int();
		__bic_SR_register_on_exit(CPUOFF);
	}
	P1IFG = 0;
}
