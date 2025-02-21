#include "printk.h"
#include "vm.h"
#include "proc.h"
#include "../arch/riscv/include/defs.h"
extern void test();
int start_kernel() {
    printk("2024 ZJU Operating System\n");
    schedule();
    test();
    return 0;
}
