    .extern start_kernel
    .extern TIMECLOCK
    .extern sbi_ecall
    .extern _traps
    .extern early_pgtbl
    .extern active_pagetable
    .section .text.init
    .globl _start
    # .globl relocate
# include "defs.h"
STIE = 0x01 << 5
SIE = 0x01 << 1
_start:
    la sp, boot_stack_top

    la a0, _traps
    csrw stvec, a0

    li a0, STIE
    csrs sie, a0
    

    # li a0, SIE
    # csrs sstatus, a0

    call setup_vm
    call relocate
    call mm_init
    call setup_vm_final
    call task_init
    call clock_init

    call start_kernel

relocate:
    # set ra = ra + PA2VA_OFFSET
    # set sp = sp + PA2VA_OFFSET (If you have set the sp before)

    li t1, PA2VA_OFFSET
    add ra, ra, t1
    add sp, sp, t1

    # set satp with early_pgtbl

    la t0, early_pgtbl      # PPN
    srli t1, t0, 12         
    li   t2, 8              # MODE
    slli  t2, t2, 60        
    or   t1, t1, t2         
    li   t2, 0xf0000fffffffffff  # ASID
    and  t1, t1, t2         

    li t5, PA2VA_OFFSET
    csrr t4, stvec
    la t3, vm_set_vec
    add t3, t3, t5
    add t4, t4, t5
    
    csrw stvec, t3          


    # flush tlb
    sfence.vma zero, zero

    # flush icache
    fence.i

    csrw satp, t1

vm_set_vec:
    csrw stvec, t4

    li a0, SIE
    csrs sstatus, a0


    # flush tlb
    sfence.vma zero, zero

    # flush icache
    fence.i

    ret



    .section .bss.stack
    .globl boot_stack
boot_stack:
    .space 0x1000 # <-- change to your stack size

    .globl boot_stack_top
boot_stack_top: