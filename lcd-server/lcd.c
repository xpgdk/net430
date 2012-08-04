#include <msp430.h>

#include "lcd.h"
#include "cpu.h"

#define SHIFT_CLOCK_PORT(V)             P2 ## V
#define SHIFT_CLOCK                     BIT4

#define SHIFT_INPUT_PORT(V)             P2 ## V
#define SHIFT_INPUT                     BIT5

#define SHIFT_LATCH_PORT(V)             P2 ## V
#define SHIFT_LATCH                     BIT3

#define SR_RS                           BIT4
#define SR_CLOCK                        BIT5
#define SR_BACKLIGHT                    BIT6

/* Private functions */
static void lcd_shift_set(unsigned char value);
static void lcd_set4(unsigned char val);
static void lcd_clock(void);
static void lcd_command(unsigned char val);
static void lcd_update_state(void);

/* Private variables */
static unsigned char lcd_shift_val = 0x0;
static unsigned char lcd_state = 0x0;
static unsigned char lcd_row_count;
static unsigned char lcd_column_count;

void
lcd_init(unsigned char columnCount, unsigned char rowCount) {
  lcd_row_count = rowCount;
  lcd_column_count = columnCount;
  SHIFT_CLOCK_PORT(DIR) |= SHIFT_CLOCK;
  SHIFT_INPUT_PORT(DIR) |= SHIFT_INPUT;
  SHIFT_LATCH_PORT(DIR) |= SHIFT_LATCH;

  SHIFT_CLOCK_PORT(OUT) &= ~SHIFT_CLOCK;
  SHIFT_INPUT_PORT(OUT) &= ~SHIFT_INPUT;
  SHIFT_LATCH_PORT(OUT) &= ~SHIFT_LATCH;

  // Ensure that all output are zero, without wasting an MSP430-pin on the
  // shift registers reset pin.
  lcd_shift_set(0x00);

  delayMs(50); // >40ms from Vcc > 2.7V

  lcd_set4(0x30);
  lcd_clock();
  delayMs(5); // > 4.1ms

  lcd_set4(0x30);
  lcd_clock();
  delayMs(1); // > 100us

  lcd_set4(0x20);
  lcd_clock();

  delayMs(1); // Wait for instruction to finish

  lcd_command(0x01);
  delayMs(10); // Wait for instruction to finish

  if( rowCount > 1 ) {
    lcd_command(0x28);
  } else {
    lcd_command(0x20);
  }
  delayMs(10); // Wait for instruction to finish
  lcd_command(0x08);
  delayMs(10); // Wait for instruction to finish
  lcd_command(0x0F);
  delayMs(10); // Wait for instruction to finish

  lcd_state = BIT2; // On by default
}

void
lcd_putchar(char c) {
  // Set RS (will be set when lcd_shift_set is called)
  lcd_shift_val |= SR_RS;

  lcd_set4(c & 0xf0);
  lcd_clock();

  lcd_set4((c<<4) & 0xf0);
  lcd_clock();

  lcd_shift_val &= ~SR_RS;
  lcd_shift_set(lcd_shift_val);
}

void
lcd_putstring(const char *str) {
  while(*str != '\0') {
    lcd_putchar(*str);
    delayMs(1);
    str++;
  }
}

void
lcd_home(void) {
  lcd_command(0x02);
}

void
lcd_clear(void) {
  lcd_command(0x01);
}

void
lcd_clear_row(unsigned char row) {
  lcd_goto(0,row);
  for(int i=0; i<lcd_column_count; i++) {
    lcd_putchar(' ');
  }
  lcd_goto(0,row);
}

void
lcd_off(void) {
  lcd_state &= ~BIT2;
  lcd_update_state();
}

void
lcd_on(void) {
  lcd_state |= BIT2;
  lcd_update_state();
}

void
lcd_cursor(bool show) {
  if( show == true) {
    lcd_state |= BIT1;
  } else {
    lcd_state &= ~BIT1;
  }
  lcd_update_state();
}

void
lcd_blink(bool on) {
  if( on == true) {
    lcd_state |= BIT0;
  } else {
    lcd_state &= ~BIT0;
  }
  lcd_update_state();

}

void
lcd_backlight(bool on)
{
  if( on == true) {
    lcd_shift_val |= SR_BACKLIGHT;
  } else {
    lcd_shift_val &= ~SR_BACKLIGHT;
  }
  lcd_shift_set(lcd_shift_val);
}

void
lcd_goto(unsigned char column, unsigned char row) {
  // Second row starts at 0x40
  unsigned char address;

  address = column + 0x40*row;
  lcd_command(0x80 | address);
}

void
lcd_shift_set(unsigned char val) {
  int i;
  for(i=0;i<8;i++) {
    if( (val & 0x80) != 0)  {
      SHIFT_INPUT_PORT(OUT) |= SHIFT_INPUT;
    } else {
      SHIFT_INPUT_PORT(OUT) &= ~SHIFT_INPUT;
    }
    SHIFT_CLOCK_PORT(OUT) |= SHIFT_CLOCK;
    //delay_cycles(1000);
    SHIFT_CLOCK_PORT(OUT) &= ~SHIFT_CLOCK;

    val = val << 1;
  }

  SHIFT_LATCH_PORT(OUT) |= SHIFT_LATCH;
  //delay_cycles(1000);
  SHIFT_LATCH_PORT(OUT) &= ~SHIFT_LATCH;
}

void
lcd_set4(unsigned char val) {
  // Reset data bits (lower 4 bits)
  lcd_shift_val &= ~0x0F;
  lcd_shift_val |= (val >> 4) & 0x0F;

  lcd_shift_set(lcd_shift_val);
}

void
lcd_clock(void) {
  lcd_shift_val |= SR_CLOCK;
  lcd_shift_set(lcd_shift_val);
  // As long as we run at 1MHz no delay is needed.
  // Otherwise we need to ensure a 1000ns delay here (actually only 450ns, but
  // the minimum clock-rise to clock-rise cycle is 1000ns).
  delayMs(2);
  lcd_shift_val &= ~SR_CLOCK;
  lcd_shift_set(lcd_shift_val);
}

void
lcd_command(unsigned char val) {
  lcd_set4(val & 0xF0);
  lcd_clock();

  lcd_set4((val << 4) & 0xF0);
  lcd_clock();

  delayMs(5);
}

void
lcd_update_state(void) {
  lcd_command(0x8 | lcd_state);
}

