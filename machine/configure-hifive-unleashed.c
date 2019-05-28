#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "config.h"
#include "disabled_hart_mask.h"
#include "fdt.h"
#include "fdtutil.h"
#include "htif.h"
#include "mtrap.h"
#include "probe.h"
#include "uart.h"
#include "uart16550.h"

static int hart_count;

//////////////////////////////////////////// MEMORY SCAN /////////////////////////////////////////


static void query_mem(void *context)
{
  mem_size = 0x200000000; /* 8GiB on the HiFive Unleashed */
}

///////////////////////////////////////////// SOC SCAN /////////////////////////////////////////

static void query_soc(void *context)
{
  uintptr_t clint_base = 0x2000000;

  plic_ndevs = 53;
  hart_count = 5;
  hart_mask |= (1 << hart_count) - 1; /* 5 harts on the FU540 */
  disabled_hart_mask = 0x1; /* hart 0, the E51 core */

  mtime = (void*)(clint_base + 0xbff8);

  for (int hart = 0; hart < hart_count; ++hart)
    hls_init(hart);

  for (int hart = 0; hart < hart_count; ++hart) {
    hls_t *hls = OTHER_HLS(hart);
    hls->ipi = (void*)(clint_base + hart * 4);
    hls->timecmp = (void*)(clint_base + 0x4000 + (hart * 8));
  }
}

///////////////////////////////////////////// PLIC SCAN /////////////////////////////////////////

#define HART_BASE	0x200000
#define HART_SIZE	0x1000
#define ENABLE_BASE	0x2000
#define ENABLE_SIZE	0x80

static void query_plic(void *context)
{
  const uintptr_t reg = 0xc000000;
  hls_t *hls;

  hls = OTHER_HLS(0);
  hls->plic_m_ie     = (uintptr_t*)(reg + ENABLE_BASE);
  hls->plic_m_thresh = (uint32_t*) (reg + HART_BASE);

  for (int hart = 1; hart < hart_count; ++hart) {
    hls = OTHER_HLS(hart);
    hls->plic_m_ie     = (uintptr_t*)(reg + ENABLE_BASE + ENABLE_SIZE * hart);
    hls->plic_m_thresh = (uint32_t*) (reg + HART_BASE   + HART_SIZE   * hart);
    hls->plic_s_ie     = (uintptr_t*)(reg + ENABLE_BASE + ENABLE_SIZE * hart);
    hls->plic_s_thresh = (uint32_t*) (reg + HART_BASE   + HART_SIZE   * hart);
  }

#if 0
  printm("PLIC: devs %d\r\n", plic_ndevs);
  for (int i = 0; i < MAX_HARTS; ++i) {
    hls_t *hls = OTHER_HLS(i);
    printm("CPU %d: %x %x %x %x\r\n", i, (uint32_t)(uintptr_t)hls->plic_m_ie, (uint32_t)(uintptr_t)hls->plic_m_thresh, (uint32_t)(uintptr_t)hls->plic_s_ie, (uint32_t)(uintptr_t)hls->plic_s_thresh);
  }
#endif
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
