#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "common.h"
#include "config.h"
#include "disabled_hart_mask.h"
#include "fdt.h"
#include "fdtutil.h"
#include "htif.h"
#include "mtrap.h"
#include "probe.h"
#include "uart.h"
#include "uart16550.h"

//////////////////////////////////////////// MEMORY SCAN /////////////////////////////////////////


static void query_mem(void *context)
{
  mem_size = 0x200000000; /* 8GiB on the HiFive Unleashed */
}

///////////////////////////////////////////// SOC SCAN /////////////////////////////////////////

static void query_soc(void *context)
{
  uintptr_t clint_base = 0x2000000;
  int hart_count = 5;

  plic_ndevs = 53;
  hart_mask |= (1 << hart_count) - 1; /* 5 harts on the FU540 */
  disabled_hart_mask = 0x1; /* hart 0, the E51 core */

  common_setup_soc(clint_base, hart_count);
}

///////////////////////////////////////////// PLIC SCAN /////////////////////////////////////////

static void query_plic(void *context)
{
  common_setup_plic(0xc000000); /* PLIC address */
}


//////////////////////////// UART //////////////////////////////

static void query_uart(void *context)
{
  // Enable Rx/Tx channels
  uart = (void *)0x10010000;
  uart_enable_rx_tx();
}

//////////////////////////////////////////// CONFIG RECORD ///////////////////////////////////////////

struct machine_config_method hifive_unleashed_config_method = {
   .config_mem = query_mem,
   .config_harts = query_soc,
   .config_clint = query_noop,
   .config_plic = query_plic,
   .config_uart = query_uart,
   .config_uart16550 = query_noop,
   .config_htif = query_noop,
   .config_finisher = query_noop,
   .filter_harts = filter_harts_noop,
   .filter_plic = query_noop,
   .filter_compat = filter_compat_noop,
};
