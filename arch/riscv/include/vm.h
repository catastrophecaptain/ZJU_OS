#ifndef __VM_H__
#define __VM_H__

#include "stdint.h"
#include "defs.h"
#define VPN(va, level) ((va) >> (39 - (level)*9) & 0x1ff)
// sizelevel: 1 for 1GB, 2 for 2MB, 3 for 4KB
// #define MAKEPTE(ppn,flag,sizelevel) ((ppn) << 37-9*(sizelevel) | (flag))
#define ADDR2PPN(addr,sizelevel) (((addr) >> (39-9*(sizelevel)))&(0xffffffffffffffff>>(47-9*(sizelevel))))
#define PPN2ADDR(ppn,sizelevel) (((ppn) << (39-9*(sizelevel))))
#define PTE2PPN(pte,sizelevel) (((pte) >> (37-9*(sizelevel)))&(0xffffffffffffffff>>(47-9*(sizelevel))))
#define PTE2FLAG(pte) ((pte) & 0x1ff)
#define PTE2ADDR(pte,sizelevel) (PPN2ADDR(PTE2PPN(pte,sizelevel),sizelevel))
#define PPN2PTE(ppn,flag,sizelevel) (((ppn) << (37-9*(sizelevel))) | (flag))
#define ADDR2PTE(addr,flag,sizelevel) (PPN2PTE(ADDR2PPN(addr,sizelevel),flag,sizelevel))
#define PA2VA(addr) ((uint64_t)(addr) - (uint64_t)PHY_START + (uint64_t)VM_START)
#define VA2PA(addr) ((uint64_t)(addr) - (uint64_t)VM_START + (uint64_t)PHY_START)
typedef uint64_t pte_t;
typedef pte_t *pagetable_ptr_t;

#define PTE_V 0x001ULL
#define PTE_R 0x002ULL
#define PTE_W 0x004ULL
#define PTE_X 0x008ULL
#define PTE_U 0x010ULL
#define PTE_G 0x020ULL
#define PTE_A 0x040ULL
#define PTE_D 0x080ULL

struct vm_area_struct {
    struct mm_struct *vm_mm;    // 所属的 mm_struct
    uint64_t vm_start;          // VMA 对应的用户态虚拟地址的开始
    uint64_t vm_end;            // VMA 对应的用户态虚拟地址的结束
    struct vm_area_struct *vm_next, *vm_prev;   // 链表指针
    uint64_t vm_flags;          // VMA 对应的 flags
    // struct file *vm_file;    // 对应的文件（目前还没实现，而且我们只有一个 uapp 所以暂不需要）
    uint64_t vm_pgoff;          // 如果对应了一个文件，那么这块 VMA 起始地址对应的文件内容相对文件起始位置的偏移量
    uint64_t vm_filesz;         // 对应的文件内容的长度
};

struct mm_struct {
    struct vm_area_struct *mmap;
};

void create_mapping(uint64_t *pgtbl, uint64_t va, uint64_t pa, uint64_t sz, uint64_t perm);
void memcpy(void *dst, void *src, uint64_t n);
void copy_pgtbl(pagetable_ptr_t dst,pagetable_ptr_t src);
pte_t *walk(pagetable_ptr_t pagetable, uint64_t va, int alloc, int *level);


struct vm_area_struct *find_vma(struct mm_struct *mm, uint64_t addr);
uint64_t do_mmap(struct mm_struct *mm, uint64_t addr, uint64_t len, uint64_t vm_pgoff, uint64_t vm_filesz, uint64_t flags);
void vmas_lazy_copy(struct mm_struct *new_mm, struct mm_struct *old_mm, pagetable_ptr_t new_pagetable, pagetable_ptr_t old_pagetable);
void vmas_deep_copy(struct mm_struct *new_mm, struct mm_struct *old_mm,pagetable_ptr_t new_pagetable,pagetable_ptr_t old_pagetable);
void vma_pages_lazy_copy(pagetable_ptr_t new_pagetable, pagetable_ptr_t old_pagetable, uint64_t start, uint64_t end);
void flush_tlb();
#define VM_ANON 0x1
#define VM_READ 0x2
#define VM_WRITE 0x4
#define VM_EXEC 0x8
#endif