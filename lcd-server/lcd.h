#ifndef LCD_H_
#define LCD_H_

#include <stdbool.h>

void lcd_init(unsigned char columnCount, unsigned char rowCount);
void lcd_putchar(char c);
void lcd_putstring(const char *str);
void lcd_home(void);
void lcd_clear(void);
void lcd_clear_row(unsigned char row);
void lcd_off(void);
void lcd_on(void);
void lcd_cursor(bool show);
void lcd_blink(bool on);
void lcd_backlight(bool on);
void lcd_goto(unsigned char column, unsigned char row);

#endif
