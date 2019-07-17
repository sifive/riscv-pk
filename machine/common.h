#ifndef _MACHINE_COMMON_H
#define _MACHINE_COMMON_H

void common_setup_soc(uintptr_t clint_base, int hart_count_l);
void common_setup_plic(uintptr_t plic_base);

#endif /* _MACHINE_COMMON_H */
