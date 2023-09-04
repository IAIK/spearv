// See LICENSE for license details.

#include "mtrap.h"
#include "bits.h"
#include "config.h"

/*
  .data
  .align 6
interrupt_table:
  .dc.a interrupt_trap           //  0 User software interrupt
  .dc.a interrupt_trap           //  1 Supervisor software interrupt
  .dc.a interrupt_trap           //  2 Reserved
  .dc.a interrupt_trap           //  3 Machine software interrupt
  .dc.a interrupt_trap           //  4 User timer interrupt
  .dc.a interrupt_trap           //  5 Supervisor timer interrupt
  .dc.a interrupt_trap           //  6 Reserved
  .dc.a interrupt_trap           //  7 Machine timer interrupt
  .dc.a interrupt_trap           //  8 User external interrupt
  .dc.a interrupt_trap           //  9 Supervisor external interrupt
  .dc.a interrupt_trap           // 10 Reserved
  .dc.a interrupt_trap           // 11 Machine external interrupt
*/


.globl trap_vector
.globl trap_vector_enclave

  .data
  .align 6
trap_table:
#define BAD_TRAP_VECTOR 0
  .dc.a bad_trap                 //  0 Instruction address misaligned
  .dc.a pmp_trap                 //  1 Instruction access fault
  .dc.a illegal_insn_trap        //  2 illegal instruction
  .dc.a bad_trap                 //  3 breakpoint
  .dc.a misaligned_load_trap     //  4 Load address misaligned
  .dc.a pmp_trap                 //  5 Load access fault
  .dc.a misaligned_store_trap    //  6 Store/AMO address misaligned
  .dc.a pmp_trap                 //  7 Store/AMO access fault
  .dc.a bad_trap                 //  8 Environment call from U-mode
  .dc.a mcall_trap               //  9 Environment call from S-mode
  .dc.a bad_trap                 // 10 Reserved
#ifdef BBL_BOOT_MACHINE
  .dc.a mcall_trap               // 11 Environment call from M-mode
#else
  .dc.a bad_trap                 // 11 Environment call from M-mode
#endif /* BBL_BOOT_MACHINE */
  .dc.a bad_trap                 // 12 Instruction page fault
#define TRAP_FROM_MACHINE_MODE_VECTOR 13
  .dc.a __trap_from_machine_mode // 13 Load page fault
  .dc.a bad_trap                 // 14 Reserved
  .dc.a bad_trap                 // 15 Store/AMO page fault
  .dc.a bad_trap                 // 16 Reserved
  .dc.a bad_trap                 // 17 Reserved
  .dc.a bad_trap                 // 18 Reserved
  .dc.a bad_trap                 // 19 Reserved
  .dc.a bad_trap                 // 20 Reserved
  .dc.a bad_trap                 // 21 Reserved
  .dc.a bad_trap                 // 22 Reserved
  .dc.a bad_trap                 // 23 Reserved
  .dc.a bad_trap                 // 24 Reserved
  .dc.a mpkey_mismatch_trap      // 25 MPKEY mismatch
  .dc.a enclave_access_trap      // 26 EAM mismatch
  .dc.a bad_trap                 // 27 MEID  mismatch
  .dc.a enc_integrity_trap       // 28 Enclave integrity violated
  .dc.a satp_mode_change_trap    // 29 S-Mode tried disabeling VM
  .dc.a bad_trap                 // 30 Reserved
  .dc.a hpce_trap                // 31 huge page containing enclave fault
  .option norvc
  .section .text.init,"ax",@progbits
  .globl reset_vector
reset_vector:
  j do_reset

//------------------------------------------------------------------------------
trap_vector_enclave:
  csrrw sp, mscratch, sp
  beqz sp, .Ltrap_from_machine_mode

  STORE a0, 10*REGBYTES(sp)
  STORE a1, 11*REGBYTES(sp)

  csrr a1, mcause
  bgez a1, .Lhandle_trap_in_machine_mode

  # This is an interrupt.

  # Preserve the registers.  Compute the address of the trap handler.
  STORE ra, 1*REGBYTES(sp)
  STORE gp, 3*REGBYTES(sp)
  STORE tp, 4*REGBYTES(sp)
  STORE t0, 5*REGBYTES(sp)
  STORE t1, 6*REGBYTES(sp)
  STORE t2, 7*REGBYTES(sp)
  STORE s0, 8*REGBYTES(sp)
  STORE s1, 9*REGBYTES(sp)
  STORE a2,12*REGBYTES(sp)
  STORE a3,13*REGBYTES(sp)
  csrrw t0, mscratch, x0           # t0 <- user sp
  STORE a4,14*REGBYTES(sp)
  STORE a5,15*REGBYTES(sp)
  STORE a6,16*REGBYTES(sp)
  STORE a7,17*REGBYTES(sp)
  STORE s2,18*REGBYTES(sp)
  STORE s3,19*REGBYTES(sp)
  STORE s4,20*REGBYTES(sp)
  STORE s5,21*REGBYTES(sp)
  STORE s6,22*REGBYTES(sp)
  STORE s7,23*REGBYTES(sp)
  STORE s8,24*REGBYTES(sp)
  STORE s9,25*REGBYTES(sp)
  STORE s10,26*REGBYTES(sp)
  STORE s11,27*REGBYTES(sp)
  STORE t3,28*REGBYTES(sp)
  STORE t4,29*REGBYTES(sp)
  STORE t5,30*REGBYTES(sp)
  STORE t6,31*REGBYTES(sp)
  STORE t0, 2*REGBYTES(sp)         # sp
  STORE x0, (sp) # Zero x0's save slot.

  mv a0, sp
  li a1, 0
  call trap_vector_enclave_c
  //li a0, 2
  //STORE a0, 10*REGBYTES(sp)

  j restore_mscratch
//------------------------------------------------------------------------------


trap_vector:
  csrrw sp, mscratch, sp
  beqz sp, .Ltrap_from_machine_mode

  STORE a0, 10*REGBYTES(sp)
  STORE a1, 11*REGBYTES(sp)

  csrr a1, mcause
  bgez a1, .Lhandle_trap_in_machine_mode

  # This is an interrupt.  Discard the mcause MSB and decode the rest.
  sll a1, a1, 1
/*
  //handle enclave interrupts
//#ifdef SM_INTERRUPT_HANDLING
  //-----------------------
  __trap_vector_enclave:
  csrr a0, CSR_U_MEID
  beqz a0, .Linterrupt_not_enclave // if MEID is zero, we are not in an enclave

  li a0, IRQ_M_SOFT * 2 // IPI
  beq a0, a1, .Linterrupt_not_enclave // skip if IPI

  //li a0, IRQ_S_SOFT * 2
  //bne a0, a1, .Linterrupt_not_enclave

  srl a1, a1, 1 //shift back to original value
  j .Lhandle_enclave_interrupt_in_machine_mode //a1 = mcause

.Linterrupt_not_enclave:
//#endif // SM_INTERRUPT_HANDLING
*/

  # Is it a machine timer interrupt?
  li a0, IRQ_M_TIMER * 2
  bne a0, a1, 1f

  # Yes.  Simply clear MTIE and raise STIP.
  li a0, MIP_MTIP
  csrc mie, a0
  li a0, MIP_STIP
  csrs mip, a0

.Lmret:
  # Go back whence we came.
  LOAD a0, 10*REGBYTES(sp)
  LOAD a1, 11*REGBYTES(sp)
  csrrw sp, mscratch, sp
  mret

1:
  # Is it an IPI?
  li a0, IRQ_M_SOFT * 2
  bne a0, a1, .Lbad_trap

  # Yes.  First, clear the MIPI bit.
  LOAD a0, MENTRY_IPI_OFFSET(sp)
  sw x0, (a0)
  fence

  # Now, decode the cause(s).
#ifdef __riscv_atomic
  addi a0, sp, MENTRY_IPI_PENDING_OFFSET
  amoswap.w a0, x0, (a0)
#else
  lw a0, MENTRY_IPI_PENDING_OFFSET(sp)
  sw x0, MENTRY_IPI_PENDING_OFFSET(sp)
#endif
  and a1, a0, IPI_SOFT
  beqz a1, 1f
  csrs mip, MIP_SSIP
1:
  andi a1, a0, IPI_FENCE_I
  beqz a1, 1f
  fence.i
1:
  andi a1, a0, IPI_SFENCE_VMA
  beqz a1, 1f
  sfence.vma
1:
  andi a1, a0, IPI_HALT
  beqz a1, 1f
  wfi
  j 1b
1:
  j .Lmret

/*
.Lhandle_enclave_interrupt_in_machine_mode:
  # Preserve the registers.  Compute the address of the trap handler.
  STORE ra, 1*REGBYTES(sp)
  STORE gp, 3*REGBYTES(sp)
  STORE tp, 4*REGBYTES(sp)
  STORE t0, 5*REGBYTES(sp)
1:auipc t0, %pcrel_hi(interrupt_table)  # t0 <- %hi(interrupt_table)
  STORE t1, 6*REGBYTES(sp)
  sll t1, a1, LOG_REGBYTES         # t1 <- mcause * ptr size
  STORE t2, 7*REGBYTES(sp)
  add t1, t0, t1                   # t1 <- %hi(trap_table)[mcause]
  STORE s0, 8*REGBYTES(sp)
  LOAD t1, %pcrel_lo(1b)(t1)       # t1 <- trap_table[mcause]
  // the rest is the same as in Lhandle_trap_in_machine_mode
  j .Lhandle_trap_in_machine_mode_after_loading_trap_table
*/
.Lhandle_trap_in_machine_mode:
  # Preserve the registers.  Compute the address of the trap handler.
  STORE ra, 1*REGBYTES(sp)
  STORE gp, 3*REGBYTES(sp)
  STORE tp, 4*REGBYTES(sp)
  STORE t0, 5*REGBYTES(sp)
1:auipc t0, %pcrel_hi(trap_table)  # t0 <- %hi(trap_table)
  STORE t1, 6*REGBYTES(sp)
  sll t1, a1, LOG_REGBYTES         # t1 <- mcause * ptr size
  STORE t2, 7*REGBYTES(sp)
  add t1, t0, t1                   # t1 <- %hi(trap_table)[mcause]
  STORE s0, 8*REGBYTES(sp)
  LOAD t1, %pcrel_lo(1b)(t1)       # t1 <- trap_table[mcause]
.Lhandle_trap_in_machine_mode_after_loading_trap_table:
  STORE s1, 9*REGBYTES(sp)
  mv a0, sp                        # a0 <- regs
  STORE a2,12*REGBYTES(sp)
  csrr a2, mepc                    # a2 <- mepc
  STORE a3,13*REGBYTES(sp)
  csrrw t0, mscratch, x0           # t0 <- user sp
  STORE a4,14*REGBYTES(sp)
  STORE a5,15*REGBYTES(sp)
  STORE a6,16*REGBYTES(sp)
  STORE a7,17*REGBYTES(sp)
  STORE s2,18*REGBYTES(sp)
  STORE s3,19*REGBYTES(sp)
  STORE s4,20*REGBYTES(sp)
  STORE s5,21*REGBYTES(sp)
  STORE s6,22*REGBYTES(sp)
  STORE s7,23*REGBYTES(sp)
  STORE s8,24*REGBYTES(sp)
  STORE s9,25*REGBYTES(sp)
  STORE s10,26*REGBYTES(sp)
  STORE s11,27*REGBYTES(sp)
  STORE t3,28*REGBYTES(sp)
  STORE t4,29*REGBYTES(sp)
  STORE t5,30*REGBYTES(sp)
  STORE t6,31*REGBYTES(sp)
  STORE t0, 2*REGBYTES(sp)         # sp

#ifndef __riscv_flen
  lw tp, (sp) # Move the emulated FCSR from x0's save slot into tp.
#endif
  STORE x0, (sp) # Zero x0's save slot.

  # Invoke the handler.
  jalr t1

#ifndef __riscv_flen
  sw tp, (sp) # Move the emulated FCSR from tp into x0's save slot.
#endif

restore_mscratch:
  # Restore mscratch, so future traps will know they didn't come from M-mode.
  csrw mscratch, sp

restore_regs:
  # Restore all of the registers.
  LOAD ra, 1*REGBYTES(sp)
  LOAD gp, 3*REGBYTES(sp)
  LOAD tp, 4*REGBYTES(sp)
  LOAD t0, 5*REGBYTES(sp)
  LOAD t1, 6*REGBYTES(sp)
  LOAD t2, 7*REGBYTES(sp)
  LOAD s0, 8*REGBYTES(sp)
  LOAD s1, 9*REGBYTES(sp)
  LOAD a0,10*REGBYTES(sp)
  LOAD a1,11*REGBYTES(sp)
  LOAD a2,12*REGBYTES(sp)
  LOAD a3,13*REGBYTES(sp)
  LOAD a4,14*REGBYTES(sp)
  LOAD a5,15*REGBYTES(sp)
  LOAD a6,16*REGBYTES(sp)
  LOAD a7,17*REGBYTES(sp)
  LOAD s2,18*REGBYTES(sp)
  LOAD s3,19*REGBYTES(sp)
  LOAD s4,20*REGBYTES(sp)
  LOAD s5,21*REGBYTES(sp)
  LOAD s6,22*REGBYTES(sp)
  LOAD s7,23*REGBYTES(sp)
  LOAD s8,24*REGBYTES(sp)
  LOAD s9,25*REGBYTES(sp)
  LOAD s10,26*REGBYTES(sp)
  LOAD s11,27*REGBYTES(sp)
  LOAD t3,28*REGBYTES(sp)
  LOAD t4,29*REGBYTES(sp)
  LOAD t5,30*REGBYTES(sp)
  LOAD t6,31*REGBYTES(sp)
  LOAD sp, 2*REGBYTES(sp)
  mret

.Ltrap_from_machine_mode:
  csrr sp, mscratch
  addi sp, sp, -INTEGER_CONTEXT_SIZE
  STORE a0,10*REGBYTES(sp)
  STORE a1,11*REGBYTES(sp)
  li a1, TRAP_FROM_MACHINE_MODE_VECTOR
  j .Lhandle_trap_in_machine_mode

.Lbad_trap:
  li a1, BAD_TRAP_VECTOR
  j .Lhandle_trap_in_machine_mode

  .globl __redirect_trap
__redirect_trap:
  # reset sp to top of M-mode stack
  li t0, MACHINE_STACK_SIZE
  add sp, sp, t0
  neg t0, t0
  and sp, sp, t0
  addi sp, sp, -MENTRY_FRAME_SIZE
  j restore_mscratch

__trap_from_machine_mode:
  jal trap_from_machine_mode
  j restore_regs

do_reset:
  li x1, 0
  li x2, 0
  li x3, 0
  li x4, 0
  li x5, 0
  li x6, 0
  li x7, 0
  li x8, 0
  li x9, 0
// save a0 and a1; arguments from previous boot loader stage:
//  li x10, 0
//  li x11, 0
  li x12, 0
  li x13, 0
  li x14, 0
  li x15, 0
  li x16, 0
  li x17, 0
  li x18, 0
  li x19, 0
  li x20, 0
  li x21, 0
  li x22, 0
  li x23, 0
  li x24, 0
  li x25, 0
  li x26, 0
  li x27, 0
  li x28, 0
  li x29, 0
  li x30, 0
  li x31, 0
  csrw mscratch, x0

  # write mtvec and make sure it sticks
  la t0, trap_vector
  csrw mtvec, t0
  csrr t1, mtvec
1:bne t0, t1, 1b

  la sp, stacks + RISCV_PGSIZE - MENTRY_FRAME_SIZE

  csrr a3, mhartid
  slli a2, a3, RISCV_PGSHIFT
  add sp, sp, a2

  bnez a3, .LmultiHartInit

#ifdef ZERO_BSS
  # Zero out BSS; linker script provides alignment and padding
  la t0, _fbss
  la t1, _end
  beq t0, t1, 2f
1:STORE zero, 0(t0)
  addi t0, t0, REGBYTES
  bne t0, t1, 1b
2:
#endif

  # Boot on the first hart
#ifdef CUSTOM_DTS
  csrr a0, mhartid
  la a1, dtb_start
#endif
  j init_first_hart

.LmultiHartInit:
  # set MSIE bit to receive IPI
  li a2, MIP_MSIP
  csrw mie, a2

.LmultiHart:
#if MAX_HARTS > 1
  # wait for an IPI to signal that it's safe to boot
  wfi

  # masked harts never start
  la a4, disabled_hart_mask
  LOAD a4, 0(a4)
  srl a4, a4, a3
  andi a4, a4, 1
  bnez a4, .LmultiHart

  # only start if mip is set
  csrr a2, mip
  andi a2, a2, MIP_MSIP
  beqz a2, .LmultiHart

  # make sure our hart id is within a valid range
  fence
  li a2, MAX_HARTS
  bltu a3, a2, init_other_hart
#endif
  wfi
  j .LmultiHart

#ifdef CUSTOM_DTS
.section .dtb
.align 3
.global dtb_start, dtb_end
dtb_start:
.incbin "custom.dtb"
dtb_end:
#endif

  .bss
  .align RISCV_PGSHIFT
stacks:
  .skip RISCV_PGSIZE * MAX_HARTS
