#ifndef __SYSCALL_H__
#define __SYSCALL_H__
#include "stdint.h"

#define SYS_WRITE 64
#define SYS_GETPID 172
#define SYS_FORK 220
#define SYS_READ 63

struct pt_regs;
void call_syscall(struct pt_regs *regs);


#endif