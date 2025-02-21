#include "syscall.h"
#include "proc.h"
#include "printk.h"
#include "fs.h"
static uint64_t sys_write(struct pt_regs *regs);
static uint64_t sys_getpid(struct pt_regs *regs);
static uint64_t sys_fork(struct pt_regs *regs);
static uint64_t sys_read(struct pt_regs *regs);
static uint64_t (*syscall_table[])(struct pt_regs *regs) = {
    [SYS_WRITE] = sys_write,
    [SYS_GETPID] = sys_getpid,
    [SYS_FORK] = sys_fork,
    [SYS_READ] = sys_read,
};

void call_syscall(struct pt_regs *regs)
{
    int callnum = regs->x[17];
    // printk("syscall %d\n", callnum);
    if (callnum >= 0 && callnum < sizeof(syscall_table) / sizeof(syscall_table[0]) && syscall_table[callnum])
    {
        regs->x[10] = syscall_table[callnum](regs);
    }
    else
    {
        regs->x[10] = -1;
    }
    regs->sepc += 4;
}

static uint64_t sys_write(struct pt_regs *regs)
{
    int fd = regs->x[10];
    char *buf = (char *)regs->x[11];
    int count = regs->x[12];
    int64_t ret;
    struct file *file = &(current->files->fd_array[fd]);
    if (file->opened == 0) {
        printk("file not opened\n");
        return ERROR_FILE_NOT_OPEN;
    } else {
        if(!(file->perms & FILE_WRITABLE)) {
            printk("file not writable\n");
            return ERROR_FILE_NOT_OPEN;
        }
        ret = file->write(file, buf, count);
    }
    return ret;
}

static uint64_t sys_read(struct pt_regs *regs)
{
    int fd = regs->x[10];
    char *buf = (char *)regs->x[11];
    int count = regs->x[12];
    int64_t ret;
    struct file *file = &(current->files->fd_array[fd]);
    if (file->opened == 0) {
        printk("file not opened\n");
        return ERROR_FILE_NOT_OPEN;
    } else {
        if(!(file->perms & FILE_READABLE)) {
            printk("file not readable\n");
            return ERROR_FILE_NOT_OPEN;
        }
        ret = file->read(file, buf, count);
    }
    return ret;
}


static uint64_t sys_getpid(struct pt_regs *regs)
{
    return getpid();
}
static uint64_t sys_fork(struct pt_regs *regs)
{
    return fork(regs);
}