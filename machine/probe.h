#ifndef PROBE_H
#define PROBE_H

// Setup memory+clint+plic
void query_mem(uintptr_t fdt);
void query_harts(uintptr_t fdt);
void query_plic(uintptr_t fdt);
void query_clint(uintptr_t fdt);
void query_uart(uintptr_t dtb);
void query_uart16550(uintptr_t dtb);
void query_htif(uintptr_t dtb);
void query_finisher(uintptr_t dtb);

// Remove information from FDT
void filter_harts(uintptr_t fdt, long *disabled_hart_mask);
void filter_plic(uintptr_t fdt);
void filter_compat(uintptr_t fdt, const char *compat);

// The hartids of available harts
extern uint64_t hart_mask;

#endif
