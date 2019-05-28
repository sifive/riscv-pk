#include <string.h>
#include "finisher.h"
#include "fdt.h"

volatile uint32_t* finisher;

void finisher_exit(uint16_t code)
{
  if (!finisher) return;
  if (code == 0) {
    *finisher = FINISHER_PASS;
  } else {
    *finisher = code << 16 | FINISHER_FAIL;
  }
}
