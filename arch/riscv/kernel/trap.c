#include "stdint.h"
#include "clock.h"
#include "defs.h"
#include "proc.h"
#include "syscall.h"
#include "printk.h"
#include "vm.h"
#include "mm.h"
#include "string.h"
extern void schedule();

// Interrupt  | Exception Code | Description
// ---------- | -------------- | -------------------------------------
// 0          | 0              | Instruction address misaligned
// 0          | 1              | Instruction access fault
// 0          | 2              | Illegal instruction
// 0          | 3              | Breakpoint
// 0          | 4              | Load address misaligned
// 0          | 5              | Load access fault
// 0          | 6              | Store/AMO address misaligned
// 0          | 7              | Store/AMO access fault
// 0          | 8              | Environment call from U-mode
// 0          | 9              | Environment call from S-mode
// 0          | 10-11          | Reserved
// 0          | 12             | Instruction page fault
// 0          | 13             | Load page fault
// 0          | 14             | Reserved
// 0          | 15             | Store/AMO page fault
// 0          | 16-17          | Reserved
// 0          | 18             | Software check
// 0          | 19             | Hardware error
// 0          | 20-23          | Reserved
// 0          | 24-31          | Designated for custom use
// 0          | 32-47          | Reserved
// 0          | 48-63          | Designated for custom use
// 0          | ≥64            | Reserved

// Interrupt  | Exception Code   | Description
// ---------- | ---------------- | -------------------------------------------
// 1          | 0                | Reserved
// 1          | 1                | Supervisor software interrupt
// 1          | 2-4              | Reserved
// 1          | 5                | Supervisor timer interrupt
// 1          | 6-8              | Reserved
// 1          | 9                | Supervisor external interrupt
// 1          | 10-12            | Reserved
// 1          | 13               | Counter-overflow interrupt
// 1          | 14-15            | Reserved
// 1          | ≥16              | Designated for platform use

extern struct task_struct *idle;    // idle process
extern struct task_struct *current; // 指向当前运行线程的 task_struct
extern char _sramdisk[];
void do_page_fault(uint64_t bad_addr, uint64_t flags);
void do_timer()
{
    // 1. 如果当前线程是 idle 线程或当前线程时间片耗尽则直接进行调度
    // 2. 否则对当前线程的运行剩余时间减 1，若剩余时间仍然大于 0 则直接返回，否则进行调度
    if (current == idle)
        schedule();
    current->counter--;
    if ((int64_t)current->counter < 0)
        current->counter = 0;
    // printk("kernel current->counter = %d\n", current->counter);
    if (current->counter == 0)
        schedule();
}
void trap_handler(uint64_t scause, uint64_t sepc, struct pt_regs *regs)
{
    uint64_t bad_addr;

    if ((scause >> 63) == 0)
    {
        // Handle exceptions
        switch (scause)
        {
        case 0x0:
            printk("Instruction address misaligned\n");
            break;
        case 0x1:
            printk("Instruction access fault\n");
            break;
        case 0x2:
            printk("Illegal instruction\n");
            break;
        case 0x3:
            printk("Breakpoint\n");
            break;
        case 0x4:
            printk("Load address misaligned\n");
            break;
        case 0x5:
            printk("Load access fault\n");
            break;
        case 0x6:
            printk("Store/AMO address misaligned\n");
            break;
        case 0x7:
            printk("Store/AMO access fault\n");
            break;
        case 0x8:
            // printk("Environment call from U-mode\n");
            call_syscall(regs);

            return;
            break;
        case 0x9:
            printk("Environment call from S-mode\n");
            break;
        case 0xC:
            bad_addr = csr_read(stval);
            Log("Instruction page fault at %p", bad_addr);
            do_page_fault(bad_addr, VM_EXEC);
            break;
        case 0xD:
            bad_addr = csr_read(stval);
            // printk("Load page fault\n");
            Log("Load page fault at %p", bad_addr);
            do_page_fault(bad_addr, VM_READ);
            break;
        case 0xF:
            bad_addr = csr_read(stval);
            // printk("Store/AMO page fault\n");
            Log("Store/AMO page fault at %p", bad_addr);
            do_page_fault(bad_addr, VM_WRITE);
            break;
        case 0x12:
            printk("Software check\n");
            break;
        case 0x13:
            printk("Hardware error\n");
            break;
        default:
            printk("Unknown exception code: %p\n", scause);
        }
    }
    else
    {
        // Handle interrupts
        uint64_t interrupt_code = scause & (~((uint64_t)0x1 << 63));
        switch (interrupt_code)
        {
        case 0x1:
            printk("Supervisor software interrupt\n");
            break;
        case 0x5:
            clock_set_next_event();
            do_timer();
            // printk("Supervisor timer interrupt\n");
            return;
            break;
        case 0x9:
            printk("Supervisor external interrupt\n");
            break;
        case 0xD:
            printk("Counter-overflow interrupt\n");
            break;
        default:
            printk("Unknown interrupt code: %p\n", interrupt_code);
        }
    }
    // printk("sepc: %p\n", sepc);
    Log("Trap occurs at sepc = %p", sepc);
    return;
}
void handle_COW(pte_t *pte)
{
    uint64_t old_va = PA2VA(PTE2ADDR(*pte, 3));
    if (get_page_refcnt((void *)old_va) > 1)
    {
        uint64_t new_va = (uint64_t)kalloc();
        memcpy((void *)new_va, (void *)old_va, PGSIZE);
        put_page((void *)old_va);
        *pte = ADDR2PTE(VA2PA(new_va), PTE2FLAG(*pte), 3);
    }
    *pte |= PTE_W;
    flush_tlb();
}
void do_page_fault(uint64_t bad_addr, uint64_t flags)
{
    struct vm_area_struct *vma = find_vma(&(current->mm), bad_addr);
    if (vma == NULL)
    {
        Err("Page fault at %p out of vma", bad_addr);
        return;
    }
    if ((vma->vm_flags & flags) == 0)
    {
        if (flags == VM_EXEC)
        {
            Err("Page fault at %p, no exec permission", bad_addr);
        }
        else if (flags == VM_READ)
        {
            Err("Page fault at %p, no read permission", bad_addr);
        }
        else if (flags == VM_WRITE)
        {
            Err("Page fault at %p, no write permission", bad_addr);
        }
        return;
    }
    uint64_t pte_flags = PTE_V | PTE_U;
    if (vma->vm_flags & VM_EXEC)
        pte_flags |= PTE_X;
    if (vma->vm_flags & VM_WRITE)
    {
        if (flags == VM_WRITE)
        {
            int level = 3;
            pte_t *pte = walk(current->pagetable, bad_addr, 0, &level);
            if (pte && !(*pte & PTE_W) && (*pte & PTE_V))
            {
                handle_COW(pte);
                Log("handle COW for process %d at address %p", current->pid, bad_addr);
                return;
            }
        }
        pte_flags |= PTE_W;
    }
    if (vma->vm_flags & VM_READ)
        pte_flags |= PTE_R;
    uint64_t new_pg = (uint64_t)kalloc();
    memset((void *)new_pg, 0, PGSIZE);

    if (!(vma->vm_flags & VM_ANON) && vma->vm_start <= bad_addr && vma->vm_end > bad_addr)
    {
        uint64_t copy_start = PGROUNDDOWN(bad_addr) < vma->vm_start ? vma->vm_start : PGROUNDDOWN(bad_addr);
        uint64_t copy_end = (PGROUNDDOWN(bad_addr) + PGSIZE) > vma->vm_start + vma->vm_filesz ? vma->vm_start + vma->vm_filesz : (PGROUNDDOWN(bad_addr) + PGSIZE);
        if (copy_end > copy_start)
        {
            uint64_t copy_size = copy_end - copy_start;
            uint64_t copy_offset = copy_start - vma->vm_start + vma->vm_pgoff;
            memcpy((void *)new_pg + copy_start - PGROUNDDOWN(bad_addr), (void *)(_sramdisk + copy_offset), copy_size);
        }
    }
    create_mapping(current->pagetable, PGROUNDDOWN(bad_addr), VA2PA(new_pg), PGSIZE, pte_flags);
    Log("Page fault at %p, create mapping to %p", bad_addr, new_pg);
}