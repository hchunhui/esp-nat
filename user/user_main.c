#include "ets_sys.h"
#include "user_interface.h"
#include "driver/uart.h"
#include "gpio.h"

void ICACHE_FLASH_ATTR
user_init(void)
{
	struct station_config sta_conf = {
		.ssid = "",
		.password = "",
		.bssid_set = 0,
	};

#if 0
	struct softap_config ap_conf = {
		.ssid = "esp",
		.password = "12345678",
		.ssid_len = 3,
		.authmode = AUTH_WPA_WPA2_PSK,
		.max_connection = 4,
	};
#endif
	struct softap_config ap_conf = {
		.ssid = "esp",
		.ssid_len = 3,
		.authmode = AUTH_OPEN,
		.max_connection = 4,
	};


	uart_init(BIT_RATE_115200, BIT_RATE_115200);
	system_update_cpu_freq(160);
	os_printf("current cpu freq: %d\n", system_get_cpu_freq());
	gpio_init();
	os_printf("\ninit\n");
	print_lwip();

	wifi_set_opmode(3);
	wifi_station_set_config(&sta_conf);
	wifi_softap_set_config(&ap_conf);
}
