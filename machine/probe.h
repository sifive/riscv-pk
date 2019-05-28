#ifndef PROBE_H
#define PROBE_H

// TODO: use a union instead?

struct machine_config_method {
  void (*config_mem)(void *context);
  void (*config_harts)(void *context);
  void (*config_plic)(void *context);
  void (*config_clint)(void *context);
  void (*config_uart)(void *context);
  void (*config_uart16550)(void *context);
  void (*config_htif)(void *context);
  void (*config_finisher)(void *context);
  void (*filter_harts)(void *context, long *disabled_hart_mask);
  void (*filter_plic)(void *context);
  void (*filter_compat)(void *context, const char *compat);
};

extern struct machine_config_method fdt_config_method;

struct machine_config_method *cm;

// The hartids of available harts
extern uint64_t hart_mask;

#endif
