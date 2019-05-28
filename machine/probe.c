#include <stdbool.h>
#include <stdint.h>
#include "config.h"
#include "probe.h"

uint64_t hart_mask;
struct machine_config_method *cm;

void query_noop(void *context) { };
void filter_harts_noop(void *context, long *disabled_hart_mask) { };
void filter_compat_noop(void *context, const char *compat) { };
