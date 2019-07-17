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

#define HART_BASE      0x200000
#define HART_SIZE      0x1000
#define ENABLE_BASE    0x2000
#define ENABLE_SIZE    0x80

static int hart_count;

/* Must be called after hart_count is set */
void common_setup_soc(uintptr_t clint_base, int hart_count_l)
{
	hart_count = hart_count_l;

	mtime = (void*)(clint_base + 0xbff8);

	for (int hart = 0; hart < hart_count; ++hart)
		hls_init(hart);

	for (int hart = 0; hart < hart_count; ++hart) {
		hls_t *hls = OTHER_HLS(hart);
		hls->ipi = (void*)(clint_base + hart * 4);
		hls->timecmp = (void*)(clint_base + 0x4000 + (hart * 8));
	}
}

/* Must be called after hart_count is set and common_setup_soc() */
void common_setup_plic(uintptr_t plic_base)
{
	hls_t *hls;

	hls = OTHER_HLS(0);
	hls->plic_m_ie     = (uintptr_t*)(plic_base + ENABLE_BASE);
	hls->plic_m_thresh = (uint32_t*) (plic_base + HART_BASE);

	for (int hart = 1; hart < hart_count; ++hart) {
		hls = OTHER_HLS(hart);
		hls->plic_m_ie     = (uintptr_t*)(plic_base + ENABLE_BASE + ENABLE_SIZE * hart);
		hls->plic_m_thresh = (uint32_t*) (plic_base + HART_BASE   + HART_SIZE   * hart);
		hls->plic_s_ie     = (uintptr_t*)(plic_base + ENABLE_BASE + ENABLE_SIZE * hart);
		hls->plic_s_thresh = (uint32_t*) (plic_base + HART_BASE   + HART_SIZE   * hart);
	}

#if 0
	printm("PLIC: devs %d\r\n", plic_ndevs);
	for (int i = 0; i < MAX_HARTS; ++i) {
		hls_t *hls = OTHER_HLS(i);
		printm("CPU %d: %x %x %x %x\r\n", i, (uint32_t)(uintptr_t)hls->plic_m_ie, (uint32_t)(uintptr_t)hls->plic_m_thresh, (uint32_t)(uintptr_t)hls->plic_s_ie, (uint32_t)(uintptr_t)hls->plic_s_thresh);
	}
#endif
}
