#ifndef PROBE_H
#define PROBE_H

// Setup memory+clint+plic
void query_mem(uintptr_t fdt);
void query_harts(uintptr_t fdt);
void query_plic(uintptr_t fdt);
void query_clint(uintptr_t fdt);

// Remove information from FDT
void filter_harts(uintptr_t fdt, long *disabled_hart_mask);
void filter_plic(uintptr_t fdt);
void filter_compat(uintptr_t fdt, const char *compat);

// The hartids of available harts
extern uint64_t hart_mask;

#endif
