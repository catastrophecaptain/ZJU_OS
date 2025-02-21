#include "mm.h"
#include "defs.h"
#include "proc.h"
#include "stdlib.h"
#include "printk.h"
#include "stdint.h"
#include "elf.h"
#include "string.h"
#include "fs.h"

extern void __dummy();
extern char _sramdisk[];
extern char _eramdisk[];
extern char __ret_from_fork[];
extern void __switch_to(struct task_struct *prev, struct task_struct *next);
struct task_struct *idle;           // idle process
struct task_struct *current;        // 指向当前运行线程的 task_struct
struct task_struct *task[NR_TASKS]; // 线程数组，所有的线程都保存在此

extern unsigned long swapper_pg_dir[512] __attribute__((__aligned__(0x1000)));

uint64_t load_binary(pagetable_ptr_t pagetable, char *start, char *end);
uint64_t load_elf(pagetable_ptr_t pagetable, char *start);
uint64_t load_elf_lazy(pagetable_ptr_t pagetable, char *start, struct task_struct *new_proc);
uint64_t getpid()
{
    return current->pid;
}

void task_init()
{
    srand(2024);
    for (int i = 0; i < NR_TASKS; i++)
    {
        task[i] = NULL;
    }
    // 1. 调用 kalloc() 为 idle 分配一个物理页
    // 2. 设置 state 为 TASK_RUNNING;
    // 3. 由于 idle 不参与调度，可以将其 counter / priority 设置为 0
    // 4. 设置 idle 的 pid 为 0
    // 5. 将 current 和 task[0] 指向 idle
    uint64_t p = (uint64_t)kalloc();
    idle = (struct task_struct *)p;
    idle->state = TASK_RUNNING;
    idle->counter = 0;
    idle->priority = 0;
    idle->pid = 0;
    current = idle;
    task[0] = idle;

    /* YOUR CODE HERE */

    // 1. 参考 idle 的设置，为 task[1] ~ task[NR_TASKS - 1] 进行初始化
    // 2. 其中每个线程的 state 为 TASK_RUNNING, 此外，counter 和 priority 进行如下赋值：
    //     - counter  = 0;
    //     - priority = rand() 产生的随机数（控制范围在 [PRIORITY_MIN, PRIORITY_MAX] 之间）
    // 3. 为 task[1] ~ task[NR_TASKS - 1] 设置 thread_struct 中的 ra 和 sp
    //     - ra 设置为 __dummy（见 4.2.2）的地址
    //     - sp 设置为该线程申请的物理页的高地址

    /* YOUR CODE HERE */
    for (int i = 0; i < 2 ; i++)
    {
        if (task[i] == NULL)
        {
            uint64_t p = (uint64_t)kalloc();
            task[i] = (struct task_struct *)p;
            task[i]->state = TASK_RUNNING;
            task[i]->counter = 0;
            task[i]->priority = PRIORITY_MIN + rand() % (PRIORITY_MAX - PRIORITY_MIN + 1);
            task[i]->pid = i;
            task[i]->thread.ra = (uint64_t)__dummy;
            task[i]->thread.sp = p + PGSIZE;
            // task[i]->thread.s[0] = dummy; // 用于指示返回的开始函数
            task[i]->thread.sstatus = csr_read(sstatus) | SPIE | SUM;
            task[i]->thread.sstatus &= (~SPP) & (~SIE);
            task[i]->thread.sscratch = USER_END;
            task[i]->pagetable = (pagetable_ptr_t)kalloc();

            copy_pgtbl(task[i]->pagetable, (pagetable_ptr_t)swapper_pg_dir);

            do_mmap(&(task[i]->mm), USER_END - PGSIZE, PGSIZE, 0, 0, VM_READ | VM_WRITE | VM_ANON);
            // load_binary(task[i]->pagetable, _sramdisk, _eramdisk);
            task[i]->thread.sepc = load_elf_lazy(task[i]->pagetable, _sramdisk, task[i]);
            
            task[i]->files = file_init();
            break;
        }
    }
    printk("...task_init done!\n");
}

uint64_t load_elf_lazy(pagetable_ptr_t pagetable, char *start, struct task_struct *new_proc)
{
    Elf64_Ehdr *elf = (Elf64_Ehdr *)start;
    for (int i = 0; i < elf->e_phnum; i++)
    {
        Elf64_Phdr *phdr = (Elf64_Phdr *)((uint64_t)start + elf->e_phoff + i * sizeof(Elf64_Phdr));
        if (phdr->p_type != PT_LOAD)
            continue;
        uint64_t flags = 0;
        if (phdr->p_flags & PF_X)
            flags |= PTE_X;
        if (phdr->p_flags & PF_W)
            flags |= PTE_W;
        if (phdr->p_flags & PF_R)
            flags |= PTE_R;
        do_mmap(&(new_proc->mm), phdr->p_vaddr, phdr->p_memsz, phdr->p_offset, phdr->p_filesz, flags);
    }
    return elf->e_entry;
}

void switch_to(struct task_struct *next)
{
    if (current == next)
        return;
    struct task_struct *prev = current;
    current = next;
    printk("switch to [PID = %d PRIORITY = %d COUNTER = %d]\n", current->pid, current->priority, current->counter);
    __switch_to(prev, next);
}

// task_init 的时候随机为各个线程赋予了优先级
// 调度时选择 counter 最大的线程运行
// 如果所有线程 counter 都为 0，则令所有线程 counter = priority
// 即优先级越高，运行的时间越长，且越先运行
// 设置完后需要重新进行调度
// 最后通过 switch_to 切换到下一个线程

void schedule()
{
    struct task_struct *next = NULL;
    // printk("schedule\n");
    for (int i = 1; i < NR_TASKS; i++)
    {
        if (task[i] == NULL || task[i]->state != TASK_RUNNING || task[i]->counter == 0)
            continue;
        if (next == NULL || task[i]->counter > next->counter)
        {
            next = task[i];
        }
    }
    // printk("new circle\n");
    if (next == NULL)
    {
        for (int i = 1; i < NR_TASKS; i++)
        {
            if (task[i] == NULL || task[i]->state != TASK_RUNNING)
                continue;
            task[i]->counter = task[i]->priority;
            if (next == NULL || task[i]->counter > next->counter)
            {
                next = task[i];
            }
        }
    }
    switch_to(next);
    return;
}

#if TEST_SCHED
#define MAX_OUTPUT ((NR_TASKS - 1) * 10)
char tasks_output[MAX_OUTPUT];
int tasks_output_index = 0;
char expected_output[] = "2222222222111111133334222222222211111113";
#include "sbi.h"
#endif

void dummy()
{
    uint64_t MOD = 1000000007;
    uint64_t auto_inc_local_var = 0;
    int last_counter = -1;
    while (1)
    {
        if ((last_counter == -1 || current->counter != last_counter) && current->counter > 0)
        {
            if (current->counter == 1)
            {
                --(current->counter); // forced the counter to be zero if this thread is going to be scheduled
            } // in case that the new counter is also 1, leading the information not printed.
            last_counter = current->counter;
            auto_inc_local_var = (auto_inc_local_var + 1) % MOD;
            printk("[PID = %d] is running. auto_inc_local_var = %d\n", current->pid, auto_inc_local_var);
#if TEST_SCHED
            tasks_output[tasks_output_index++] = current->pid + '0';
            if (tasks_output_index == MAX_OUTPUT)
            {
                for (int i = 0; i < MAX_OUTPUT; ++i)
                {
                    if (tasks_output[i] != expected_output[i])
                    {
                        printk("\033[31mTest failed!\033[0m\n");
                        printk("\033[31m    Expected: %s\033[0m\n", expected_output);
                        printk("\033[31m    Got:      %s\033[0m\n", tasks_output);
                        sbi_system_reset(SBI_SRST_RESET_TYPE_SHUTDOWN, SBI_SRST_RESET_REASON_NONE);
                    }
                }
                printk("\033[32mTest passed!\033[0m\n");
                printk("\033[32m    Output: %s\033[0m\n", expected_output);
                sbi_system_reset(SBI_SRST_RESET_TYPE_SHUTDOWN, SBI_SRST_RESET_REASON_NONE);
            }
#endif
        }
    }
}
uint64_t fork(struct pt_regs *old_regs)
{
    int pid;
    for (pid = 1; pid < NR_TASKS; pid++)
    {
        if (task[pid] == NULL)
        {
            break;
        }
    }
    if (pid == NR_TASKS)
    {
        Err("No more process can be created\n");
        return -1;
    }
    uint64_t kernel_stack = (uint64_t)kalloc();
    pagetable_ptr_t pagetable = (pagetable_ptr_t)kalloc();
    memcpy((void *)kernel_stack, (void *)current, PGSIZE);
    task[pid] = (struct task_struct *)kernel_stack;
    task[pid]->pid = pid;
    task[pid]->pagetable = pagetable;
    task[pid]->mm.mmap = NULL;
    copy_pgtbl(task[pid]->pagetable, (pagetable_ptr_t)swapper_pg_dir);
    vmas_lazy_copy(&(task[pid]->mm), &(current->mm), task[pid]->pagetable, current->pagetable);
    task[pid]->thread.ra = (uint64_t)__ret_from_fork;
    task[pid]->thread.sp = kernel_stack + PGSIZE - sizeof(struct pt_regs);
    task[pid]->thread.sscratch = 0;
    struct pt_regs *regs = (struct pt_regs *)(kernel_stack + PGSIZE - sizeof(struct pt_regs));
    regs->x[10] = 0;
    regs->sepc += 4;
    Log("fork: pid = %d", pid);
    return pid;
}
