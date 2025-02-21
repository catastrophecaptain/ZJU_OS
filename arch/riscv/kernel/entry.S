    .extern trap_handler
    .section .text.entry
    .align 2
    .globl _traps
    .extern current
#define SPP     0x100
# #define PAGEOFFSET_CLEAR 0xfffffffffffff000
_traps:

    csrrw sp, sscratch, sp
    bnez sp, _usertrap

_kerneltrap:
    .cfi_startproc
    .cfi_def_cfa sp, 0

    csrrw sp, sscratch, sp
    sd x2, -240(sp)       
    addi sp, sp, -256
    .cfi_def_cfa sp, 256   
    sd x1, 0(sp)          
    csrr x1, sepc
    sd x1, 248(sp)
    sd x3, 24(sp)         
    sd x4, 32(sp)         
    sd x5, 40(sp)         
    sd x6, 48(sp)         
    sd x7, 56(sp)         
    sd x8, 240(sp)         
    addi x8, sp, 256
    .cfi_offset x1, -8
    .cfi_offset x8, -16
    sd x9, 72(sp)         
    sd x10, 80(sp)        
    sd x11, 88(sp)        
    sd x12, 96(sp)        
    sd x13, 104(sp)       
    sd x14, 112(sp)       
    sd x15, 120(sp)       
    sd x16, 128(sp)       
    sd x17, 136(sp)       
    sd x18, 144(sp)       
    sd x19, 152(sp)       
    sd x20, 160(sp)       
    sd x21, 168(sp)       
    sd x22, 176(sp)       
    sd x23, 184(sp)       
    sd x24, 192(sp)       
    sd x25, 200(sp)       
    sd x26, 208(sp)       
    sd x27, 216(sp)       
    sd x28, 224(sp)       
    sd x29, 232(sp)       
    sd x30, 64(sp)       
    sd x31, 8(sp)

    csrr a0, scause
    csrr a1, sepc
    addi a2, x0, 0
    call trap_handler

    ld a0, 248(sp)
    csrw sepc, a0
    ld x1, 0(sp)          
    ld x3, 24(sp)         
    ld x4, 32(sp)         
    ld x5, 40(sp)         
    ld x6, 48(sp)         
    ld x7, 56(sp)         
    ld x8, 240(sp)         
    ld x9, 72(sp)         
    ld x10, 80(sp)        
    ld x11, 88(sp)        
    ld x12, 96(sp)        
    ld x13, 104(sp)       
    ld x14, 112(sp)       
    ld x15, 120(sp)       
    ld x16, 128(sp)       
    ld x17, 136(sp)       
    ld x18, 144(sp)       
    ld x19, 152(sp)       
    ld x20, 160(sp)       
    ld x21, 168(sp)       
    ld x22, 176(sp)       
    ld x23, 184(sp)       
    ld x24, 192(sp)       
    ld x25, 200(sp)       
    ld x26, 208(sp)       
    ld x27, 216(sp)       
    ld x28, 224(sp)       
    ld x29, 232(sp)       
    ld x30, 64(sp)       
    ld x31, 8(sp)       
    ld x2, 16(sp)         
    sret
    .cfi_endproc

_usertrap:
    # sd x0, -272(sp)
    sd x1, -264(sp)
    # sd x2, -256(sp)
    sd x3, -248(sp)
    sd x4, -240(sp)
    sd x5, -232(sp)
    sd x6, -224(sp)
    sd x7, -216(sp)
    sd x8, -208(sp)
    sd x9, -200(sp)
    sd x10, -192(sp)
    sd x11, -184(sp)
    sd x12, -176(sp)
    sd x13, -168(sp)
    sd x14, -160(sp)
    sd x15, -152(sp)
    sd x16, -144(sp)
    sd x17, -136(sp)
    sd x18, -128(sp)
    sd x19, -120(sp)
    sd x20, -112(sp)
    sd x21, -104(sp)
    sd x22, -96(sp)
    sd x23, -88(sp)
    sd x24, -80(sp)
    sd x25, -72(sp)
    sd x26, -64(sp)
    sd x27, -56(sp)
    sd x28, -48(sp)
    sd x29, -40(sp)
    sd x30, -32(sp)
    sd x31, -24(sp)
    csrr t1, sepc
    sd t1, -16(sp)
    csrr t2, sstatus
    sd t2, -8(sp)
    csrr t3, sscratch
    sd t3, -256(sp)

    addi sp, sp, -272
    csrr a0, scause
    csrr a1, sepc
    addi a2, sp, 0
    call trap_handler
    # only sp is saved
    .globl __ret_from_fork
__ret_from_fork:

    addi sp, sp, 272
    ld t1, -16(sp)
    csrw sepc, t1
    ld t2, -8(sp)
    csrw sstatus, t2
    csrw sscratch, sp
    # ld x0, -272(sp)
    ld x1, -264(sp)
    # ld x2, -256(sp)
    ld x3, -248(sp)
    ld x4, -240(sp)
    ld x5, -232(sp)
    ld x6, -224(sp)
    ld x7, -216(sp)
    ld x8, -208(sp)
    ld x9, -200(sp)
    ld x10, -192(sp)
    ld x11, -184(sp)
    ld x12, -176(sp)
    ld x13, -168(sp)
    ld x14, -160(sp)
    ld x15, -152(sp)
    ld x16, -144(sp)
    ld x17, -136(sp)
    ld x18, -128(sp)
    ld x19, -120(sp)
    ld x20, -112(sp)
    ld x21, -104(sp)
    ld x22, -96(sp)
    ld x23, -88(sp)
    ld x24, -80(sp)
    ld x25, -72(sp)
    ld x26, -64(sp)
    ld x27, -56(sp)
    ld x28, -48(sp)
    ld x29, -40(sp)
    ld x30, -32(sp)
    ld x31, -24(sp)
    ld x2, -256(sp)
    sret

    


# struct pt_regs {
#     uint64_t x[32];
#     uint64_t sepc;
#     uint64_t sstatus;
# };


    # 1. save 32 registers and sepc to stack
    # 2. call trap_handler
    # 3. restore sepc and 32 registers (x2(sp) should be restore last) from stack
    # 4. return from trap

    # .extern dummy
    .globl __dummy
__dummy:
    csrrw sp, sscratch, sp
    sret

# struct thread_struct {
#     uint64_t ra;
#     uint64_t sp;
#     uint64_t s[12];
# 
#     uint64_t sepc, sstatus, sscratch;
# };
# 
# /* 线程数据结构 */
# struct task_struct {
#     uint64_t state;     // 线程状态
#     uint64_t counter;   // 运行剩余时间
#     uint64_t priority;  // 运行优先级 1 最低 10 最高
#     uint64_t pid;       // 线程 id
# 
#     struct thread_struct thread;
# 
#     pagetable_ptr_t pagetable;
# };
    .extern set_pgtbl
    .globl __switch_to 
__switch_to:
    addi a0, a0, 0x20
    addi a1, a1, 0x20
    sd ra, 0(a0)
    sd sp, 8(a0)
    sd s0, 16(a0)
    sd s1, 24(a0)
    sd s2, 32(a0)
    sd s3, 40(a0)
    sd s4, 48(a0)
    sd s5, 56(a0)
    sd s6, 64(a0)
    sd s7, 72(a0)
    sd s8, 80(a0)
    sd s9, 88(a0)
    sd s10, 96(a0)
    sd s11, 104(a0)
    csrr s1, sepc
    csrr s2, sstatus
    csrr s3, sscratch
    sd s1, 112(a0)
    sd s2, 120(a0)
    sd s3, 128(a0)

    addi s1, a1, 0x0
    ld a0, 136(s1)
    call set_pgtbl
    addi a1, s1, 0x0

    ld s1, 112(a1)
    ld s2, 120(a1)
    ld s3, 128(a1)
    csrw sepc, s1
    csrw sstatus, s2
    csrw sscratch, s3
    ld ra, 0(a1)
    ld sp, 8(a1)
    ld s0, 16(a1)
    ld s1, 24(a1)
    ld s2, 32(a1)
    ld s3, 40(a1)
    ld s4, 48(a1)
    ld s5, 56(a1)
    ld s6, 64(a1)
    ld s7, 72(a1)
    ld s8, 80(a1)
    ld s9, 88(a1)
    ld s10, 96(a1)
    ld s11, 104(a1)
    ret



