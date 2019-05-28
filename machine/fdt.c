#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "config.h"
#include "fdt.h"
#include "fdtutil.h"
#include "finisher.h"
#include "htif.h"
#include "mtrap.h"
#include "probe.h"
#include "uart.h"
#include "uart16550.h"

//////////////////////////////////////////// MEMORY SCAN /////////////////////////////////////////

struct mem_scan {
  int memory;
  const uint32_t *reg_value;
  int reg_len;
};

static void mem_open(const struct fdt_scan_node *node, void *extra)
{
  struct mem_scan *scan = (struct mem_scan *)extra;
  memset(scan, 0, sizeof(*scan));
}

static void mem_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct mem_scan *scan = (struct mem_scan *)extra;
  if (!strcmp(prop->name, "device_type") && !strcmp((const char*)prop->value, "memory")) {
    scan->memory = 1;
  } else if (!strcmp(prop->name, "reg")) {
    scan->reg_value = prop->value;
    scan->reg_len = prop->len;
  }
}

static void mem_done(const struct fdt_scan_node *node, void *extra)
{
  struct mem_scan *scan = (struct mem_scan *)extra;
  const uint32_t *value = scan->reg_value;
  const uint32_t *end = value + scan->reg_len/4;
  uintptr_t self = (uintptr_t)mem_done;

  if (!scan->memory) return;
  assert (scan->reg_value && scan->reg_len % 4 == 0);

  while (end - value > 0) {
    uint64_t base, size;
    value = fdt_get_address(node->parent, value, &base);
    value = fdt_get_size   (node->parent, value, &size);
    if (base <= self && self <= base + size) { mem_size = size; }
  }
  assert (end == value);
}

void query_mem(uintptr_t fdt)
{
  struct fdt_cb cb;
  struct mem_scan scan;

  memset(&cb, 0, sizeof(cb));
  cb.open = mem_open;
  cb.prop = mem_prop;
  cb.done = mem_done;
  cb.extra = &scan;

  mem_size = 0;
  fdt_scan(fdt, &cb);
  assert (mem_size > 0);
}

///////////////////////////////////////////// HART SCAN //////////////////////////////////////////

static uint32_t hart_phandles[MAX_HARTS];

struct hart_scan {
  const struct fdt_scan_node *cpu;
  int hart;
  const struct fdt_scan_node *controller;
  int cells;
  uint32_t phandle;
};

static void hart_open(const struct fdt_scan_node *node, void *extra)
{
  struct hart_scan *scan = (struct hart_scan *)extra;
  if (!scan->cpu) {
    scan->hart = -1;
  }
  if (!scan->controller) {
    scan->cells = 0;
    scan->phandle = 0;
  }
}

static void hart_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct hart_scan *scan = (struct hart_scan *)extra;
  if (!strcmp(prop->name, "device_type") && !strcmp((const char*)prop->value, "cpu")) {
    assert (!scan->cpu);
    scan->cpu = prop->node;
  } else if (!strcmp(prop->name, "interrupt-controller")) {
    assert (!scan->controller);
    scan->controller = prop->node;
  } else if (!strcmp(prop->name, "#interrupt-cells")) {
    scan->cells = bswap(prop->value[0]);
  } else if (!strcmp(prop->name, "phandle")) {
    scan->phandle = bswap(prop->value[0]);
  } else if (!strcmp(prop->name, "reg")) {
    uint64_t reg;
    fdt_get_address(prop->node->parent, prop->value, &reg);
    scan->hart = reg;
  }
}

static void hart_done(const struct fdt_scan_node *node, void *extra)
{
  struct hart_scan *scan = (struct hart_scan *)extra;

  if (scan->cpu == node) {
    assert (scan->hart >= 0);
  }

  if (scan->controller == node && scan->cpu) {
    assert (scan->phandle > 0);
    assert (scan->cells == 1);

    if (scan->hart < MAX_HARTS) {
      hart_phandles[scan->hart] = scan->phandle;
      hart_mask |= 1 << scan->hart;
      hls_init(scan->hart);
    }
  }
}

static int hart_close(const struct fdt_scan_node *node, void *extra)
{
  struct hart_scan *scan = (struct hart_scan *)extra;
  if (scan->cpu == node) scan->cpu = 0;
  if (scan->controller == node) scan->controller = 0;
  return 0;
}

void query_harts(uintptr_t fdt)
{
  struct fdt_cb cb;
  struct hart_scan scan;

  memset(&cb, 0, sizeof(cb));
  memset(&scan, 0, sizeof(scan));
  cb.open = hart_open;
  cb.prop = hart_prop;
  cb.done = hart_done;
  cb.close= hart_close;
  cb.extra = &scan;

  fdt_scan(fdt, &cb);

  // The current hart should have been detected
  assert ((hart_mask >> read_csr(mhartid)) != 0);
}

///////////////////////////////////////////// CLINT SCAN /////////////////////////////////////////

struct clint_scan
{
  int compat;
  uint64_t reg;
  const uint32_t *int_value;
  int int_len;
  int done;
};

static void clint_open(const struct fdt_scan_node *node, void *extra)
{
  struct clint_scan *scan = (struct clint_scan *)extra;
  scan->compat = 0;
  scan->reg = 0;
  scan->int_value = 0;
}

static void clint_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct clint_scan *scan = (struct clint_scan *)extra;
  if (!strcmp(prop->name, "compatible") && fdt_string_list_index(prop, "riscv,clint0") >= 0) {
    scan->compat = 1;
  } else if (!strcmp(prop->name, "reg")) {
    fdt_get_address(prop->node->parent, prop->value, &scan->reg);
  } else if (!strcmp(prop->name, "interrupts-extended")) {
    scan->int_value = prop->value;
    scan->int_len = prop->len;
  }
}

static void clint_done(const struct fdt_scan_node *node, void *extra)
{
  struct clint_scan *scan = (struct clint_scan *)extra;
  const uint32_t *value = scan->int_value;
  const uint32_t *end = value + scan->int_len/4;

  if (!scan->compat) return;
  assert (scan->reg != 0);
  assert (scan->int_value && scan->int_len % 16 == 0);
  assert (!scan->done); // only one clint

  scan->done = 1;
  mtime = (void*)((uintptr_t)scan->reg + 0xbff8);

  for (int index = 0; end - value > 0; ++index) {
    uint32_t phandle = bswap(value[0]);
    int hart;
    for (hart = 0; hart < MAX_HARTS; ++hart)
      if (hart_phandles[hart] == phandle)
        break;
    if (hart < MAX_HARTS) {
      hls_t *hls = OTHER_HLS(hart);
      hls->ipi = (void*)((uintptr_t)scan->reg + index * 4);
      hls->timecmp = (void*)((uintptr_t)scan->reg + 0x4000 + (index * 8));
    }
    value += 4;
  }
}

void query_clint(uintptr_t fdt)
{
  struct fdt_cb cb;
  struct clint_scan scan;

  memset(&cb, 0, sizeof(cb));
  cb.open = clint_open;
  cb.prop = clint_prop;
  cb.done = clint_done;
  cb.extra = &scan;

  scan.done = 0;
  fdt_scan(fdt, &cb);
  assert (scan.done);
}

///////////////////////////////////////////// PLIC SCAN /////////////////////////////////////////

struct plic_scan
{
  int compat;
  uint64_t reg;
  uint32_t *int_value;
  int int_len;
  int done;
  int ndev;
};

static void plic_open(const struct fdt_scan_node *node, void *extra)
{
  struct plic_scan *scan = (struct plic_scan *)extra;
  scan->compat = 0;
  scan->reg = 0;
  scan->int_value = 0;
}

static void plic_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct plic_scan *scan = (struct plic_scan *)extra;
  if (!strcmp(prop->name, "compatible") && fdt_string_list_index(prop, "riscv,plic0") >= 0) {
    scan->compat = 1;
  } else if (!strcmp(prop->name, "reg")) {
    fdt_get_address(prop->node->parent, prop->value, &scan->reg);
  } else if (!strcmp(prop->name, "interrupts-extended")) {
    scan->int_value = prop->value;
    scan->int_len = prop->len;
  } else if (!strcmp(prop->name, "riscv,ndev")) {
    scan->ndev = bswap(prop->value[0]);
  }
}

#define HART_BASE	0x200000
#define HART_SIZE	0x1000
#define ENABLE_BASE	0x2000
#define ENABLE_SIZE	0x80

static void plic_done(const struct fdt_scan_node *node, void *extra)
{
  struct plic_scan *scan = (struct plic_scan *)extra;
  const uint32_t *value = scan->int_value;
  const uint32_t *end = value + scan->int_len/4;

  if (!scan->compat) return;
  assert (scan->reg != 0);
  assert (scan->int_value && scan->int_len % 8 == 0);
  assert (scan->ndev >= 0 && scan->ndev < 1024);
  assert (!scan->done); // only one plic

  scan->done = 1;
  plic_priorities = (uint32_t*)(uintptr_t)scan->reg;
  plic_ndevs = scan->ndev;

  for (int index = 0; end - value > 0; ++index) {
    uint32_t phandle = bswap(value[0]);
    uint32_t cpu_int = bswap(value[1]);
    int hart;
    for (hart = 0; hart < MAX_HARTS; ++hart)
      if (hart_phandles[hart] == phandle)
        break;
    if (hart < MAX_HARTS) {
      hls_t *hls = OTHER_HLS(hart);
      if (cpu_int == IRQ_M_EXT) {
        hls->plic_m_ie     = (uintptr_t*)((uintptr_t)scan->reg + ENABLE_BASE + ENABLE_SIZE * index);
        hls->plic_m_thresh = (uint32_t*) ((uintptr_t)scan->reg + HART_BASE   + HART_SIZE   * index);
      } else if (cpu_int == IRQ_S_EXT) {
        hls->plic_s_ie     = (uintptr_t*)((uintptr_t)scan->reg + ENABLE_BASE + ENABLE_SIZE * index);
        hls->plic_s_thresh = (uint32_t*) ((uintptr_t)scan->reg + HART_BASE   + HART_SIZE   * index);
      } else {
        printm("PLIC wired hart %d to wrong interrupt %d\n", hart, cpu_int);
      }
    }
    value += 2;
  }
#if 0
  printm("PLIC: prio %x devs %d\r\n", (uint32_t)(uintptr_t)plic_priorities, plic_ndevs);
  for (int i = 0; i < MAX_HARTS; ++i) {
    hls_t *hls = OTHER_HLS(i);
    printm("CPU %d: %x %x %x %x\r\n", i, (uint32_t)(uintptr_t)hls->plic_m_ie, (uint32_t)(uintptr_t)hls->plic_m_thresh, (uint32_t)(uintptr_t)hls->plic_s_ie, (uint32_t)(uintptr_t)hls->plic_s_thresh);
  }
#endif
}

void query_plic(uintptr_t fdt)
{
  struct fdt_cb cb;
  struct plic_scan scan;

  memset(&cb, 0, sizeof(cb));
  cb.open = plic_open;
  cb.prop = plic_prop;
  cb.done = plic_done;
  cb.extra = &scan;

  scan.done = 0;
  fdt_scan(fdt, &cb);
}

static void plic_redact(const struct fdt_scan_node *node, void *extra)
{
  struct plic_scan *scan = (struct plic_scan *)extra;
  uint32_t *value = scan->int_value;
  uint32_t *end = value + scan->int_len/4;

  if (!scan->compat) return;
  scan->done = 1;

  while (end - value > 0) {
    if (bswap(value[1]) == IRQ_M_EXT) value[1] = bswap(-1);
    value += 2;
  }
}

void filter_plic(uintptr_t fdt)
{
  struct fdt_cb cb;
  struct plic_scan scan;

  memset(&cb, 0, sizeof(cb));
  cb.open = plic_open;
  cb.prop = plic_prop;
  cb.done = plic_redact;
  cb.extra = &scan;

  scan.done = 0;
  fdt_scan(fdt, &cb);
}

//////////////////////////////////////////// COMPAT SCAN ////////////////////////////////////////

struct compat_scan
{
  const char *compat;
  int depth;
  int kill;
};

static void compat_open(const struct fdt_scan_node *node, void *extra)
{
  struct compat_scan *scan = (struct compat_scan *)extra;
  ++scan->depth;
}

static void compat_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct compat_scan *scan = (struct compat_scan *)extra;
  if (!strcmp(prop->name, "compatible") && fdt_string_list_index(prop, scan->compat) >= 0)
    if (scan->depth < scan->kill)
      scan->kill = scan->depth;
}

static int compat_close(const struct fdt_scan_node *node, void *extra)
{
  struct compat_scan *scan = (struct compat_scan *)extra;
  if (scan->kill == scan->depth--) {
    scan->kill = 999;
    return -1;
  } else {
    return 0;
  }
}

void filter_compat(uintptr_t fdt, const char *compat)
{
  struct fdt_cb cb;
  struct compat_scan scan;

  memset(&cb, 0, sizeof(cb));
  cb.open = compat_open;
  cb.prop = compat_prop;
  cb.close = compat_close;
  cb.extra = &scan;

  scan.compat = compat;
  scan.depth = 0;
  scan.kill = 999;
  fdt_scan(fdt, &cb);
}

//////////////////////////////////////////// HART FILTER ////////////////////////////////////////

struct hart_filter {
  int compat;
  int hart;
  char *status;
  char *mmu_type;
  long *disabled_hart_mask;
};

static void hart_filter_open(const struct fdt_scan_node *node, void *extra)
{
  struct hart_filter *filter = (struct hart_filter *)extra;
  filter->status = NULL;
  filter->mmu_type = NULL;
  filter->compat = 0;
  filter->hart = -1;
}

static void hart_filter_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct hart_filter *filter = (struct hart_filter *)extra;
  if (!strcmp(prop->name, "device_type") && !strcmp((const char*)prop->value, "cpu")) {
    filter->compat = 1;
  } else if (!strcmp(prop->name, "reg")) {
    uint64_t reg;
    fdt_get_address(prop->node->parent, prop->value, &reg);
    filter->hart = reg;
  } else if (!strcmp(prop->name, "status")) {
    filter->status = (char*)prop->value;
  } else if (!strcmp(prop->name, "mmu-type")) {
    filter->mmu_type = (char*)prop->value;
  }
}

static bool hart_filter_mask(const struct hart_filter *filter)
{
  if (filter->mmu_type == NULL) return true;
  if (strcmp(filter->status, "okay")) return true;
  if (!strcmp(filter->mmu_type, "riscv,sv39")) return false;
  if (!strcmp(filter->mmu_type, "riscv,sv48")) return false;
  printm("hart_filter_mask saw unknown hart type: status=\"%s\", mmu_type=\"%s\"\n",
         filter->status, filter->mmu_type);
  return true;
}

static void hart_filter_done(const struct fdt_scan_node *node, void *extra)
{
  struct hart_filter *filter = (struct hart_filter *)extra;

  if (!filter->compat) return;
  assert (filter->status);
  assert (filter->hart >= 0);

  if (hart_filter_mask(filter)) {
    strcpy(filter->status, "masked");
    uint32_t *len = (uint32_t*)filter->status;
    len[-2] = bswap(strlen("masked")+1);
    *filter->disabled_hart_mask |= (1 << filter->hart);
  }
}

void filter_harts(uintptr_t fdt, long *disabled_hart_mask)
{
  struct fdt_cb cb;
  struct hart_filter filter;

  memset(&cb, 0, sizeof(cb));
  cb.open = hart_filter_open;
  cb.prop = hart_filter_prop;
  cb.done = hart_filter_done;
  cb.extra = &filter;

  filter.disabled_hart_mask = disabled_hart_mask;
  *disabled_hart_mask = 0;
  fdt_scan(fdt, &cb);
}


//////////////////////////////////////////// UART //////////////////////////////////////////////

struct uart_scan
{
  int compat;
  uint64_t reg;
};

static void uart_open(const struct fdt_scan_node *node, void *extra)
{
  struct uart_scan *scan = (struct uart_scan *)extra;
  memset(scan, 0, sizeof(*scan));
}

static void uart_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct uart_scan *scan = (struct uart_scan *)extra;
  if (!strcmp(prop->name, "compatible") && !strcmp((const char*)prop->value, "sifive,uart0")) {
    scan->compat = 1;
  } else if (!strcmp(prop->name, "reg")) {
    fdt_get_address(prop->node->parent, prop->value, &scan->reg);
  }
}

static void uart_done(const struct fdt_scan_node *node, void *extra)
{
  struct uart_scan *scan = (struct uart_scan *)extra;
  if (!scan->compat || !scan->reg || uart) return;

  // Enable Rx/Tx channels
  uart = (void*)(uintptr_t)scan->reg;
  uart_enable_rx_tx();
}

void query_uart(uintptr_t fdt)
{
  struct fdt_cb cb;
  struct uart_scan scan;

  memset(&cb, 0, sizeof(cb));
  cb.open = uart_open;
  cb.prop = uart_prop;
  cb.done = uart_done;
  cb.extra = &scan;

  fdt_scan(fdt, &cb);
}

//////////////////////////////////////////// UART16550 //////////////////////////////////////////

struct uart16550_scan
{
  int compat;
  uint64_t reg;
};

static void uart16550_open(const struct fdt_scan_node *node, void *extra)
{
  struct uart16550_scan *scan = (struct uart16550_scan *)extra;
  memset(scan, 0, sizeof(*scan));
}

static void uart16550_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct uart16550_scan *scan = (struct uart16550_scan *)extra;
  if (!strcmp(prop->name, "compatible") && !strcmp((const char*)prop->value, "ns16550a")) {
    scan->compat = 1;
  } else if (!strcmp(prop->name, "reg")) {
    fdt_get_address(prop->node->parent, prop->value, &scan->reg);
  }
}

static void uart16550_done(const struct fdt_scan_node *node, void *extra)
{
  struct uart16550_scan *scan = (struct uart16550_scan *)extra;
  if (!scan->compat || !scan->reg || uart16550) return;

  uart16550 = (void*)(uintptr_t)scan->reg;
  // http://wiki.osdev.org/Serial_Ports
  uart16550[1] = 0x00;    // Disable all interrupts
  uart16550[3] = 0x80;    // Enable DLAB (set baud rate divisor)
  uart16550[0] = 0x03;    // Set divisor to 3 (lo byte) 38400 baud
  uart16550[1] = 0x00;    //                  (hi byte)
  uart16550[3] = 0x03;    // 8 bits, no parity, one stop bit
  uart16550[2] = 0xC7;    // Enable FIFO, clear them, with 14-byte threshold
}

void query_uart16550(uintptr_t fdt)
{
  struct fdt_cb cb;
  struct uart16550_scan scan;

  memset(&cb, 0, sizeof(cb));
  cb.open = uart16550_open;
  cb.prop = uart16550_prop;
  cb.done = uart16550_done;
  cb.extra = &scan;

  fdt_scan(fdt, &cb);
}

//////////////////////////////////////////// HTIF ///////////////////////////////////////////////


struct htif_scan
{
  int compat;
};

static void htif_open(const struct fdt_scan_node *node, void *extra)
{
  struct htif_scan *scan = (struct htif_scan *)extra;
  memset(scan, 0, sizeof(*scan));
}

static void htif_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct htif_scan *scan = (struct htif_scan *)extra;
  if (!strcmp(prop->name, "compatible") && !strcmp((const char*)prop->value, "ucb,htif0")) {
    scan->compat = 1;
  }
}

static void htif_done(const struct fdt_scan_node *node, void *extra)
{
  struct htif_scan *scan = (struct htif_scan *)extra;
  if (!scan->compat) return;

  htif = 1;
}

void query_htif(uintptr_t fdt)
{
  struct fdt_cb cb;
  struct htif_scan scan;

  memset(&cb, 0, sizeof(cb));
  cb.open = htif_open;
  cb.prop = htif_prop;
  cb.done = htif_done;
  cb.extra = &scan;

  fdt_scan(fdt, &cb);
}

//////////////////////////////////////////// FINISHER ///////////////////////////////////////////


struct finisher_scan
{
  int compat;
  uint64_t reg;
};

static void finisher_open(const struct fdt_scan_node *node, void *extra)
{
  struct finisher_scan *scan = (struct finisher_scan *)extra;
  memset(scan, 0, sizeof(*scan));
}

static void finisher_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct finisher_scan *scan = (struct finisher_scan *)extra;
  if (!strcmp(prop->name, "compatible") && !strcmp((const char*)prop->value, "sifive,test0")) {
    scan->compat = 1;
  } else if (!strcmp(prop->name, "reg")) {
    fdt_get_address(prop->node->parent, prop->value, &scan->reg);
  }
}

static void finisher_done(const struct fdt_scan_node *node, void *extra)
{
  struct finisher_scan *scan = (struct finisher_scan *)extra;
  if (!scan->compat || !scan->reg || finisher) return;
  finisher = (uint32_t*)(uintptr_t)scan->reg;
}

void query_finisher(uintptr_t fdt)
{
  struct fdt_cb cb;
  struct finisher_scan scan;

  memset(&cb, 0, sizeof(cb));
  cb.open = finisher_open;
  cb.prop = finisher_prop;
  cb.done = finisher_done;
  cb.extra = &scan;

  fdt_scan(fdt, &cb);
}

