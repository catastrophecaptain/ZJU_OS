#include "stdint.h"
#include "sbi.h"

struct sbiret sbi_ecall(uint64_t eid, uint64_t fid,
                        uint64_t arg0, uint64_t arg1, uint64_t arg2,
                        uint64_t arg3, uint64_t arg4, uint64_t arg5)
{
    struct sbiret ret;
    __asm__ volatile(
        " move a0, %2 \n"
        " move a1, %3 \n"
        " move a2, %4 \n"
        " move a3, %5 \n"
        " move a4, %6 \n"
        " move a5, %7 \n"
        " move a6, %8 \n"
        " move a7, %9 \n"
        " ecall \n"
        " move %0, a0 \n"
        " move %1, a1 \n"
        : "=r"(ret.error), "=r"(ret.value)
        : "r"(arg0), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4), "r"(arg5), "r"(fid), "r"(eid)
        : "memory","a0","a1","a2","a3","a4","a5","a6","a7");
    return ret;
}

struct sbiret sbi_set_timer(uint64_t stime_value)
{
    struct sbiret ret;
    ret = sbi_ecall(0x54494d45, 0x0, stime_value, 0, 0, 0, 0, 0);
    return ret;
}
struct sbiret sbi_system_reset(uint32_t reset_type, uint32_t reset_reason)
{
    struct sbiret ret;
    ret = sbi_ecall(0x53525354, 0x0, reset_type, reset_reason, 0, 0, 0, 0);
    return ret;
}
struct sbiret sbi_debug_console_write(unsigned long num_bytes, unsigned long base_addr_lo, unsigned long base_addr_hi)
{
    struct sbiret ret;
    ret = sbi_ecall(0x4442434e, 0x0, num_bytes, base_addr_lo, base_addr_hi, 0, 0, 0);
    return ret;
}
struct sbiret sbi_debug_console_read(unsigned long num_bytes, unsigned long base_addr_lo, unsigned long base_addr_hi)
{
    struct sbiret ret;
    ret = sbi_ecall(0x4442434e, 0x1, num_bytes, base_addr_lo, base_addr_hi, 0, 0, 0);
    return ret;
}
struct sbiret sbi_debug_console_write_byte(uint8_t byte)
{
    struct sbiret ret;
    ret = sbi_ecall(0x4442434e, 0x2, byte, 0, 0, 0, 0, 0);
    return ret;
}
