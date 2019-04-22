#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "config.h"
#include "fdt.h"
#include "mtrap.h"

uint64_t hart_mask;

static inline uint32_t bswap(uint32_t x)
{
  uint32_t y = (x & 0x00FF00FF) <<  8 | (x & 0xFF00FF00) >>  8;
  uint32_t z = (y & 0x0000FFFF) << 16 | (y & 0xFFFF0000) >> 16;
  return z;
}

static inline int isstring(char c)
{
  if (c >= 'A' && c <= 'Z')
    return 1;
  if (c >= 'a' && c <= 'z')
    return 1;
  if (c >= '0' && c <= '9')
    return 1;
  if (c == '\0' || c == ' ' || c == ',' || c == '-')
    return 1;
  return 0;
}

static uint32_t *fdt_scan_helper(
  uint32_t *lex,
  const char *strings,
  struct fdt_scan_node *node,
  const struct fdt_cb *cb)
{
  struct fdt_scan_node child;
  struct fdt_scan_prop prop;
  int last = 0;

  child.parent = node;
  // these are the default cell counts, as per the FDT spec
  child.address_cells = 2;
  child.size_cells = 1;
  prop.node = node;

  while (1) {
    switch (bswap(lex[0])) {
      case FDT_NOP: {
        lex += 1;
        break;
      }
      case FDT_PROP: {
        assert (!last);
        prop.name  = strings + bswap(lex[2]);
        prop.len   = bswap(lex[1]);
        prop.value = lex + 3;
        if (node && !strcmp(prop.name, "#address-cells")) { node->address_cells = bswap(lex[3]); }
        if (node && !strcmp(prop.name, "#size-cells"))    { node->size_cells    = bswap(lex[3]); }
        lex += 3 + (prop.len+3)/4;
        cb->prop(&prop, cb->extra);
        break;
      }
      case FDT_BEGIN_NODE: {
        uint32_t *lex_next;
        if (!last && node && cb->done) cb->done(node, cb->extra);
        last = 1;
        child.name = (const char *)(lex+1);
        if (cb->open) cb->open(&child, cb->extra);
        lex_next = fdt_scan_helper(
          lex + 2 + strlen(child.name)/4,
          strings, &child, cb);
        if (cb->close && cb->close(&child, cb->extra) == -1)
          while (lex != lex_next) *lex++ = bswap(FDT_NOP);
        lex = lex_next;
        break;
      }
      case FDT_END_NODE: {
        if (!last && node && cb->done) cb->done(node, cb->extra);
        return lex + 1;
      }
      default: { // FDT_END
        if (!last && node && cb->done) cb->done(node, cb->extra);
        return lex;
      }
    }
  }
}

void fdt_scan(uintptr_t fdt, const struct fdt_cb *cb)
{
  struct fdt_header *header = (struct fdt_header *)fdt;

  // Only process FDT that we understand
  if (bswap(header->magic) != FDT_MAGIC ||
      bswap(header->last_comp_version) > FDT_VERSION) return;

  const char *strings = (const char *)(fdt + bswap(header->off_dt_strings));
  uint32_t *lex = (uint32_t *)(fdt + bswap(header->off_dt_struct));

  fdt_scan_helper(lex, strings, 0, cb);
}

uint32_t fdt_size(uintptr_t fdt)
{
  struct fdt_header *header = (struct fdt_header *)fdt;

  // Only process FDT that we understand
  if (bswap(header->magic) != FDT_MAGIC ||
      bswap(header->last_comp_version) > FDT_VERSION) return 0;
  return bswap(header->totalsize);
}

const uint32_t *fdt_get_address(const struct fdt_scan_node *node, const uint32_t *value, uint64_t *result)
{
  *result = 0;
  for (int cells = node->address_cells; cells > 0; --cells)
    *result = (*result << 32) + bswap(*value++);
  return value;
}

const uint32_t *fdt_get_size(const struct fdt_scan_node *node, const uint32_t *value, uint64_t *result)
{
  *result = 0;
  for (int cells = node->size_cells; cells > 0; --cells)
    *result = (*result << 32) + bswap(*value++);
  return value;
}

int fdt_string_list_index(const struct fdt_scan_prop *prop, const char *str)
{
  const char *list = (const char *)prop->value;
  const char *end = list + prop->len;
  int index = 0;
  while (end - list > 0) {
    if (!strcmp(list, str)) return index;
    ++index;
    list += strlen(list) + 1;
  }
  return -1;
}

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

///////////////////////////////////////////// SOC SCAN /////////////////////////////////////////

struct soc_scan
{
  int compat;
  uint64_t reg;
  int done;
  int harts;
};

static void soc_open(const struct fdt_scan_node *node, void *extra)
{
  struct soc_scan *scan = (struct soc_scan *)extra;
  scan->compat = 0;
  scan->reg = 0;
  scan->harts = 0;
  /* XXX plic_ndevs ? */
}

static void soc_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct soc_scan *scan = (struct soc_scan *)extra;

  /* XXX Should look for this along a particular path instead */
  if (!scan->done && !strcmp(prop->name, "compatible") && fdt_string_list_index(prop, "sifive,fu540-c000") >= 0) {
    scan->compat = 1; /* XXX should be an SoC type constant */
    scan->reg = 0x2000000;
    scan->harts = 5;
    plic_ndevs = 53;
  }
}

static void soc_done(const struct fdt_scan_node *node, void *extra)
{
  struct soc_scan *scan = (struct soc_scan *)extra;

  if (!scan->compat) return;
  assert (scan->reg != 0);
  assert (!scan->done); // only one soc

  scan->done = 1;
  mtime = (void*)((uintptr_t)scan->reg + 0xbff8);

  hart_mask |= 0x1f; /* 5 harts on the FU540 */
  disabled_hart_mask = 0x1; /* hart 0 */
  for (int hart = 0; hart < scan->harts; ++hart)
    hls_init(hart);

  for (int hart = 0; hart < scan->harts; ++hart) {
    hls_t *hls = OTHER_HLS(hart);
    hls->ipi = (void*)((uintptr_t)scan->reg + hart * 4);
    hls->timecmp = (void*)((uintptr_t)scan->reg + 0x4000 + (hart * 8));
  }
}

void query_soc(uintptr_t fdt)
{
  struct fdt_cb cb;
  struct soc_scan scan;

  memset(&cb, 0, sizeof(cb));
  cb.open = soc_open;
  cb.prop = soc_prop;
  cb.done = soc_done;
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
  if (!strcmp(prop->name, "compatible") && fdt_string_list_index(prop, "sifive,plic-1.0.0") >= 0) {
    scan->compat = 1;
  } else if (!strcmp(prop->name, "reg")) {
    fdt_get_address(prop->node->parent, prop->value, &scan->reg);
  } else if (!strcmp(prop->name, "interrupts-extended")) {
    scan->int_value = prop->value;
    scan->int_len = prop->len;
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
  assert (!scan->done); // only one plic

  scan->done = 1;
  plic_priorities = (uint32_t*)(uintptr_t)scan->reg;

  int hart = 0;
  for (int index = 0; end - value > 0; ++index) {
    uint32_t phandle = bswap(value[0]);
    uint32_t cpu_int = bswap(value[1]);
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
    hart += 1;
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

//////////////////////////////////////////// PRINT //////////////////////////////////////////////

#ifdef PK_PRINT_DEVICE_TREE
#define FDT_PRINT_MAX_DEPTH 32

struct fdt_print_info {
  int depth;
  const struct fdt_scan_node *stack[FDT_PRINT_MAX_DEPTH];
};

void fdt_print_printm(struct fdt_print_info *info, const char *format, ...)
{
  va_list vl;

  for (int i = 0; i < info->depth; ++i)
    printm("  ");

  va_start(vl, format);
  vprintm(format, vl);
  va_end(vl);
}

static void fdt_print_open(const struct fdt_scan_node *node, void *extra)
{
  struct fdt_print_info *info = (struct fdt_print_info *)extra;

  while (node->parent != NULL && info->stack[info->depth-1] != node->parent) {
    info->depth--;
    fdt_print_printm(info, "}\r\n");
  }

  fdt_print_printm(info, "%s {\r\n", node->name);
  info->stack[info->depth] = node;
  info->depth++;
}

static void fdt_print_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct fdt_print_info *info = (struct fdt_print_info *)extra;
  int asstring = 1;
  char *char_data = (char *)(prop->value);

  fdt_print_printm(info, "%s", prop->name);

  if (prop->len == 0) {
    printm(";\r\n");
    return;
  } else {
    printm(" = ");
  }

  /* It appears that dtc uses a hueristic to detect strings so I'm using a
   * similar one here. */
  for (int i = 0; i < prop->len; ++i) {
    if (!isstring(char_data[i]))
      asstring = 0;
    if (i > 0 && char_data[i] == '\0' && char_data[i-1] == '\0')
      asstring = 0;
  }

  if (asstring) {
    for (size_t i = 0; i < prop->len; i += strlen(char_data + i) + 1) {
      if (i != 0)
        printm(", ");
      printm("\"%s\"", char_data + i);
    }
  } else {
    printm("<");
    for (size_t i = 0; i < prop->len/4; ++i) {
      if (i != 0)
        printm(" ");
      printm("0x%08x", bswap(prop->value[i]));
    }
    printm(">");
  }

  printm(";\r\n");
}

static void fdt_print_done(const struct fdt_scan_node *node, void *extra)
{
  struct fdt_print_info *info = (struct fdt_print_info *)extra;
}

static int fdt_print_close(const struct fdt_scan_node *node, void *extra)
{
  struct fdt_print_info *info = (struct fdt_print_info *)extra;
  return 0;
}

void fdt_print(uintptr_t fdt)
{
  struct fdt_print_info info;
  struct fdt_cb cb;

  info.depth = 0;

  memset(&cb, 0, sizeof(cb));
  cb.open = fdt_print_open;
  cb.prop = fdt_print_prop;
  cb.done = fdt_print_done;
  cb.close = fdt_print_close;
  cb.extra = &info;

  fdt_scan(fdt, &cb);

  while (info.depth > 0) {
    info.depth--;
    fdt_print_printm(&info, "}\r\n");
  }
}
#endif
