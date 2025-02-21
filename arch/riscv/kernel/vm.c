/* early_pgtbl: 用于 setup_vm 进行 1GiB 的映射 */
#include "vm.h"
#include "mm.h"
#include "string.h"
#include "printk.h"
unsigned long early_pgtbl[512] __attribute__((__aligned__(0x1000)));
/* swapper_pg_dir: kernel pagetable 根目录，在 setup_vm_final 进行映射 */
unsigned long swapper_pg_dir[512] __attribute__((__aligned__(0x1000)));
extern char _ekernel[], _skernel[], _stext[], _etext[], _srodata[], _erodata[], _sdata[], _edata[], _sbss[], _ebss[];

// If active_pagetable is NULL, then the kernel does not open the virtual memory.
// pagetable_ptr_t active_pagetable;

/*
If return != 0, walk returns the address of the PTE for a given virtual address.
If alloc != 0, walk allocates a new page table page for a given virtual address if one doesn't exist.
If level == 0, don't return level, but if alloc != 0, return 0.
If *level == 0, return the level of the page table entry, but if alloc != 0, return 0.
If *level == 1 or 2 or 3, return the address of the PTE for a given virtual address and the given level.
*/
pte_t *walk(pagetable_ptr_t pagetable, uint64_t va, int alloc, int *level)
{
    int set_level = !(level == 0 || *level == 0);
    if (!set_level && alloc != 0)
    {
        return 0;
    }
    if (level != 0 && (*level < 0 || *level > 3))
    {
        return 0;
    }
    pte_t *pte;
    int current_level = 1;
    pagetable_ptr_t current_pagetable = pagetable;
    for (; current_level < (set_level ? *level : 3); current_level++)
    {
        pte = &(current_pagetable[VPN(va, current_level)]);
        if (*pte & PTE_V)
        {
            if ((*pte & PTE_R) || (*pte & PTE_W) || (*pte & PTE_X))
            {
                break;
            }
            current_pagetable = (pagetable_ptr_t)PA2VA(PTE2ADDR(*pte, 3));
        }
        else if (alloc == 0)
        {
            return 0;
        }
        else
        {
            pagetable_ptr_t new_pagetable = (pagetable_ptr_t)kalloc();
            if (new_pagetable == 0)
            {
                return 0;
            }
            memset(new_pagetable, 0, PGSIZE);
            *pte = ADDR2PTE((uint64_t)(VA2PA((uint64_t)new_pagetable)), PTE_V, 3);
            current_pagetable = new_pagetable;
        }
    }
    // printk("1");
    if (set_level && current_level != *level)
    {
        // printk("walk: level not match\n");
        return 0;
    }
    if (!set_level && level != 0)
    {
        *level = current_level;
    }
    return &((current_pagetable[VPN(va, current_level)]));
}

void setup_vm(void)
{
    /*
     * 1. 由于是进行 1GiB 的映射，这里不需要使用多级页表
     * 2. 将 va 的 64bit 作为如下划分： | high bit | 9 bit | 30 bit |
     *     high bit 可以忽略
     *     中间 9 bit 作为 early_pgtbl 的 index
     *     低 30 bit 作为页内偏移，这里注意到 30 = 9 + 9 + 12，即我们只使用根页表，根页表的每个 entry 都对应 1GiB 的区域
     * 3. Page Table Entry 的权限 V | R | W | X 位设置为 1
     **/
    memset(early_pgtbl, 0, PGSIZE);
    pte_t *pte;
    int level = 1;
    pte = (pte_t *)&early_pgtbl[VPN(VM_START, level)];
    *pte = ADDR2PTE(PHY_START, PTE_V | PTE_R | PTE_W | PTE_X, 1);
    // pte = (pte_t *)&early_pgtbl[VPN(PHY_START, level)];
    // *pte = ADDR2PTE(PHY_START, PTE_V | PTE_R | PTE_W | PTE_X, 1);
    // printk("%d",1);
}

/* 创建多级页表映射关系 */
/* 不要修改该接口的参数和返回值 */
void create_mapping(uint64_t *pgtbl, uint64_t va, uint64_t pa, uint64_t sz, uint64_t perm)
{
    if (sz % PGSIZE != 0)
    {
        printk("create_mapping: size is not page aligned\n");
    }
    if (va % PGSIZE != 0)
    {
        printk("create_mapping: va is not page aligned\n");
    }
    if (pa % PGSIZE != 0)
    {
        printk("create_mapping: pa is not page aligned\n");
    }
    int pgcnt = sz / PGSIZE;
    int level = 3;
    for (int i = 0; i < pgcnt; i++)
    {
        pte_t *pte = walk((pagetable_ptr_t)pgtbl, va + i * PGSIZE, 1, &level);
        if (pte == 0)
        {
            printk("create_mapping: walk failed\n");
        }
        *pte = ADDR2PTE(pa + i * PGSIZE, perm, level);
    }
    Log("create_mapping: [%p, %p) -> [%p, %p) with perm %p", va, va + sz, pa, pa + sz, perm);
}

// the pgtbl is VA
void set_pgtbl(uint64_t *pgtbl)
{
    uint64_t satp = VA2PA((uint64_t)pgtbl) >> 12;
    asm volatile(
        "fence\n"
        "fence.i\n"
        "sfence.vma zero, zero\n"
        "csrr t1, satp \n"
        "li t2, 0xfffff00000000000 \n"
        "li t3, 0x00000fffffffffff \n"
        "and t1, t1, t2 \n"
        "and t3, %0, t3 \n"
        "or t1, t1, t3 \n"
        "csrw satp, t1 \n"
        "fence\n"
        "fence.i\n"
        "sfence.vma zero, zero\n"
        :
        : "r"(satp)
        : "memory");
}
void show_pgtbl(uint64_t *pgtbl)
{
    for (int i = 0; i < 512; i++)
    {
        if (pgtbl[i] & PTE_V)
        {
            printk("VPN: %p\n", i);
            printk("PTE: %p\n", pgtbl[i]);
            if (!(pgtbl[i] & PTE_R) && !(pgtbl[i] & PTE_W) && !(pgtbl[i] & PTE_X))
            {
                pagetable_ptr_t current_pagetable1 = (pagetable_ptr_t)PA2VA(PTE2ADDR(pgtbl[i], 3));
                for (int j = 0; j < 512; j++)
                {
                    if (current_pagetable1[j] & PTE_V)
                    {
                        printk("\tVPN: %p\n", j);
                        printk("\tPTE: %p\n", current_pagetable1[j]);
                        if (!(pgtbl[i] & PTE_R) && !(pgtbl[i] & PTE_W) && !(pgtbl[i] & PTE_X))
                        {
                            pagetable_ptr_t current_pagetable2 = (pagetable_ptr_t)PA2VA(PTE2ADDR(current_pagetable1[j], 3));
                            for (int k = 0; k < 512; k++)
                            {
                                if (current_pagetable2[k] & PTE_V)
                                {
                                    printk("\t\tVPN: %p\n", k);
                                    printk("\t\tPTE: %p\n", current_pagetable2[k]);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

void setup_vm_final(void)
{
    memset((uint64_t *)swapper_pg_dir, 0x0, PGSIZE);

    // No OpenSBI mapping required

    // mapping kernel text X|-|R|V
    create_mapping((uint64_t *)swapper_pg_dir, (uint64_t)_stext, VA2PA(_stext), PGROUNDUP(_etext - _stext), PTE_R | PTE_X | PTE_V);

    // mapping kernel rodata -|-|R|V
    create_mapping((uint64_t *)swapper_pg_dir, (uint64_t)_srodata, VA2PA(_srodata), PGROUNDUP(_erodata - _srodata), PTE_R | PTE_V);

    // mapping other memory -|W|R|V
    // create_mapping((uint64_t *)swapper_pg_dir, (uint64_t)_sdata, VA2PA(_sdata), PGROUNDUP(_edata - _sdata), PTE_R | PTE_W | PTE_V);
    // create_mapping((uint64_t *)swapper_pg_dir, (uint64_t)_sbss, VA2PA(_sbss), PGROUNDUP(_ebss - _sbss), PTE_R | PTE_W | PTE_V);
    // create_mapping((uint64_t *)swapper_pg_dir, PGROUNDUP((uint64_t)_ebss), VA2PA(PGROUNDUP((uint64_t)_ebss)), PHY_END - VA2PA(PGROUNDUP((uint64_t)_ebss)), PTE_R | PTE_W | PTE_V);
    create_mapping((uint64_t *)swapper_pg_dir, (uint64_t)_sdata, VA2PA(_sdata), PGROUNDUP(PHY_SIZE + VM_START - (uint64_t)_sdata), PTE_R | PTE_W | PTE_V);
    // printk("%x\n",(uint64_t)_stext);
    // set satp with swapper_pg_dir

    // YOUR CODE HERE

    set_pgtbl((uint64_t *)swapper_pg_dir);
    // show_pgtbl(swapper_pg_dir);

    return;
}
void copy_pgtbl(pagetable_ptr_t dst, pagetable_ptr_t src)
{
    memcpy((void *)dst, (void *)src, PGSIZE);
    for (int i = 0; i < 512; i++)
    {
        if (src[i] & PTE_V)
        {
            if (!(src[i] & PTE_R) && !(src[i] & PTE_W) && !(src[i] & PTE_X))
            {
                pagetable_ptr_t current_pagetable1 = (pagetable_ptr_t)PA2VA(PTE2ADDR(src[i], 3));
                pagetable_ptr_t new_pagetable1 = (pagetable_ptr_t)kalloc();
                dst[i] = ADDR2PTE((uint64_t)VA2PA((uint64_t)new_pagetable1), PTE_V, 3);
                memcpy((void *)new_pagetable1, (void *)current_pagetable1, PGSIZE);
                for (int j = 0; j < 512; j++)
                {
                    if (current_pagetable1[j] & PTE_V)
                    {
                        if (!(current_pagetable1[j] & PTE_R) && !(current_pagetable1[j] & PTE_W) && !(current_pagetable1[j] & PTE_X))
                        {
                            pagetable_ptr_t current_pagetable2 = (pagetable_ptr_t)PA2VA(PTE2ADDR(current_pagetable1[j], 3));
                            pagetable_ptr_t new_pagetable2 = (pagetable_ptr_t)kalloc();
                            new_pagetable1[j] = ADDR2PTE((uint64_t)VA2PA((uint64_t)new_pagetable2), PTE_V, 3);
                            memcpy((void *)new_pagetable2, (void *)current_pagetable2, PGSIZE);
                        }
                    }
                }
            }
        }
    }
    // printk("copy_pgtbl done!\n");
}
/*
 * @mm       : current thread's mm_struct
 * @addr     : the va to look up
 *
 * @return   : the VMA if found or NULL if not found
 */
struct vm_area_struct *find_vma(struct mm_struct *mm, uint64_t addr)
{
    struct vm_area_struct *vma = mm->mmap;
    while (vma != NULL)
    {
        if (vma->vm_start <= addr && vma->vm_end > addr)
        {
            return vma;
        }
        vma = vma->vm_next;
    }
    return vma;
}

/*
 * @mm       : current thread's mm_struct
 * @addr     : the suggested va to map
 * @len      : memory size to map
 * @vm_pgoff : phdr->p_offset
 * @vm_filesz: phdr->p_filesz
 * @flags    : flags for the new VMA
 *
 * @return   : start va
 */
uint64_t do_mmap(struct mm_struct *mm, uint64_t addr, uint64_t len, uint64_t vm_pgoff, uint64_t vm_filesz, uint64_t flags)
{
    struct vm_area_struct *new_vma = (struct vm_area_struct *)kalloc();
    new_vma->vm_mm = mm;
    new_vma->vm_start = addr;
    new_vma->vm_end = addr + len;
    new_vma->vm_flags = flags;
    new_vma->vm_pgoff = vm_pgoff;
    new_vma->vm_filesz = vm_filesz;
    new_vma->vm_next = mm->mmap;
    new_vma->vm_prev = NULL;
    if (mm->mmap != NULL)
    {
        mm->mmap->vm_prev = new_vma;
    }
    mm->mmap = new_vma;
    Log("construct vma: [%p, %p) with flags %p for mm %p", new_vma->vm_start, new_vma->vm_end, new_vma->vm_flags, mm);
    return addr;
}
void vmas_lazy_copy(struct mm_struct *new_mm, struct mm_struct *old_mm, pagetable_ptr_t new_pagetable, pagetable_ptr_t old_pagetable)
{
    for (struct vm_area_struct *vma = old_mm->mmap; vma != NULL; vma = vma->vm_next)
    {
        do_mmap(new_mm, vma->vm_start, vma->vm_end - vma->vm_start, vma->vm_pgoff, vma->vm_filesz, vma->vm_flags);
        vma_pages_lazy_copy(new_pagetable, old_pagetable, PGROUNDDOWN(vma->vm_start), PGROUNDUP(vma->vm_end));
    }
    flush_tlb();
}
void vma_pages_copy(pagetable_ptr_t new_pagetable, pagetable_ptr_t old_pagetable, uint64_t start, uint64_t end)
{
    for (uint64_t va = start; va < end; va += PGSIZE)
    {
        int level = 3;
        pte_t *pte = walk(old_pagetable, va, 0, &level);
        if (pte == 0 || !(*pte & PTE_V))
        {
            continue;
        }
        uint64_t old_pa = PTE2ADDR(*pte, 3);
        uint64_t old_va = PA2VA(old_pa);
        uint64_t new_pa = (uint64_t)kalloc();
        memcpy((void *)new_pa, (void *)old_va, PGSIZE);
        create_mapping(new_pagetable, va, VA2PA(new_pa), PGSIZE, PTE2FLAG(*pte));
    }
}

void vma_pages_lazy_copy(pagetable_ptr_t new_pagetable, pagetable_ptr_t old_pagetable, uint64_t start, uint64_t end)
{
    for (uint64_t va = start; va < end; va += PGSIZE)
    {
        int level = 3;
        pte_t *pte = walk(old_pagetable, va, 0, &level);
        if (pte == 0 || !(*pte & PTE_V))
        {
            continue;
        }
        if ((*pte & PTE_W))
        {
            *pte &= ~PTE_W;
        }
        get_page((void *)PA2VA(PTE2ADDR(*pte, 3)));
        create_mapping(new_pagetable, va, PTE2ADDR(*pte, 3), PGSIZE, PTE2FLAG(*pte));
    }
}

void vmas_deep_copy(struct mm_struct *new_mm, struct mm_struct *old_mm, pagetable_ptr_t new_pagetable, pagetable_ptr_t old_pagetable)
{
    for (struct vm_area_struct *vma = old_mm->mmap; vma != NULL; vma = vma->vm_next)
    {
        do_mmap(new_mm, vma->vm_start, vma->vm_end - vma->vm_start, vma->vm_pgoff, vma->vm_filesz, vma->vm_flags);
        vma_pages_copy(new_pagetable, old_pagetable, PGROUNDDOWN(vma->vm_start), PGROUNDUP(vma->vm_end));
    }
}

void flush_tlb()
{
    asm volatile("sfence.vma zero, zero");
    asm volatile("fence.i");
    asm volatile("fence");
}