#ifndef _RISCV_DEVICE_H
#define _RISCV_DEVICE_H

extern volatile uint32_t* uart;

#define UART_DATA	0
#define UART_TXCNT	1
#define UART_RXCNT	2
#define UART_DIV	3

#endif
