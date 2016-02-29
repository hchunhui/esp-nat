#include "ets_sys.h"
#include "user_interface.h"
#include "driver/uart.h"

void ICACHE_FLASH_ATTR
user_init(void)
{
	uart_init(BIT_RATE_9600, BIT_RATE_9600);
	print_lwip();
}
