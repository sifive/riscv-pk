#ifndef FDTUTIL_H
#define FDTUTIL_H

uint32_t bswap(uint32_t x);

// Scan the contents of FDT
void fdt_scan(uintptr_t fdt, const struct fdt_cb *cb);
uint32_t fdt_size(uintptr_t fdt);

// Extract fields
const uint32_t *fdt_get_address(const struct fdt_scan_node *node, const uint32_t *base, uint64_t *value);
const uint32_t *fdt_get_size(const struct fdt_scan_node *node, const uint32_t *base, uint64_t *value);
int fdt_string_list_index(const struct fdt_scan_prop *prop, const char *str); // -1 if not found

#ifdef PK_PRINT_DEVICE_TREE
// Prints the device tree to the console as a DTS
void fdt_print(uintptr_t fdt);
#endif

#endif
