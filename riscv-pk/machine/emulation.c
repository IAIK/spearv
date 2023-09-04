// See LICENSE for license details.

#include "emulation.h"
#include "fp_emulation.h"
#include "config.h"
#include "unprivileged_memory.h"
#include "mtrap.h"
#include <limits.h>
#include "tag.h"
#include "tag_debug.h"

static DECLARE_EMULATION_FUNC(emulate_rvc)
{
#ifdef __riscv_compressed
  // the only emulable RVC instructions are FP loads and stores.
# if !defined(__riscv_flen) && defined(PK_ENABLE_FP_EMULATION)
  write_csr(mepc, mepc + 2);

  // if FPU is disabled, punt back to the OS
  if (unlikely((mstatus & MSTATUS_FS) == 0))
    return truly_illegal_insn(regs, mcause, mepc, mstatus, insn);

  if ((insn & MASK_C_FLD) == MATCH_C_FLD) {
    uintptr_t addr = GET_RS1S(insn, regs) + RVC_LD_IMM(insn);
    if (unlikely(addr % sizeof(uintptr_t)))
      return misaligned_load_trap(regs, mcause, mepc);
    SET_F64_RD(RVC_RS2S(insn) << SH_RD, regs, load_uint64_t((void *)addr, mepc));
  } else if ((insn & MASK_C_FLDSP) == MATCH_C_FLDSP) {
    uintptr_t addr = GET_SP(regs) + RVC_LDSP_IMM(insn);
    if (unlikely(addr % sizeof(uintptr_t)))
      return misaligned_load_trap(regs, mcause, mepc);
    SET_F64_RD(insn, regs, load_uint64_t((void *)addr, mepc));
  } else if ((insn & MASK_C_FSD) == MATCH_C_FSD) {
    uintptr_t addr = GET_RS1S(insn, regs) + RVC_LD_IMM(insn);
    if (unlikely(addr % sizeof(uintptr_t)))
      return misaligned_store_trap(regs, mcause, mepc);
    store_uint64_t((void *)addr, GET_F64_RS2(RVC_RS2S(insn) << SH_RS2, regs), mepc);
  } else if ((insn & MASK_C_FSDSP) == MATCH_C_FSDSP) {
    uintptr_t addr = GET_SP(regs) + RVC_SDSP_IMM(insn);
    if (unlikely(addr % sizeof(uintptr_t)))
      return misaligned_store_trap(regs, mcause, mepc);
    store_uint64_t((void *)addr, GET_F64_RS2(RVC_RS2(insn) << SH_RS2, regs), mepc);
  } else
#  if __riscv_xlen == 32
  if ((insn & MASK_C_FLW) == MATCH_C_FLW) {
    uintptr_t addr = GET_RS1S(insn, regs) + RVC_LW_IMM(insn);
    if (unlikely(addr % 4))
      return misaligned_load_trap(regs, mcause, mepc);
    SET_F32_RD(RVC_RS2S(insn) << SH_RD, regs, load_int32_t((void *)addr, mepc));
  } else if ((insn & MASK_C_FLWSP) == MATCH_C_FLWSP) {
    uintptr_t addr = GET_SP(regs) + RVC_LWSP_IMM(insn);
    if (unlikely(addr % 4))
      return misaligned_load_trap(regs, mcause, mepc);
    SET_F32_RD(insn, regs, load_int32_t((void *)addr, mepc));
  } else if ((insn & MASK_C_FSW) == MATCH_C_FSW) {
    uintptr_t addr = GET_RS1S(insn, regs) + RVC_LW_IMM(insn);
    if (unlikely(addr % 4))
      return misaligned_store_trap(regs, mcause, mepc);
    store_uint32_t((void *)addr, GET_F32_RS2(RVC_RS2S(insn) << SH_RS2, regs), mepc);
  } else if ((insn & MASK_C_FSWSP) == MATCH_C_FSWSP) {
    uintptr_t addr = GET_SP(regs) + RVC_SWSP_IMM(insn);
    if (unlikely(addr % 4))
      return misaligned_store_trap(regs, mcause, mepc);
    store_uint32_t((void *)addr, GET_F32_RS2(RVC_RS2(insn) << SH_RS2, regs), mepc);
  } else
#  endif
# endif
#endif

  return truly_illegal_insn(regs, mcause, mepc, mstatus, insn);
}

void illegal_insn_trap(uintptr_t* regs, uintptr_t mcause, uintptr_t mepc)
{
  asm (".pushsection .rodata\n"
       "illegal_insn_trap_table:\n"
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
#if !defined(__riscv_flen) && defined(PK_ENABLE_FP_EMULATION)
       "  .word emulate_float_load - illegal_insn_trap_table\n"
#else
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
#endif
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
#if !defined(__riscv_flen) && defined(PK_ENABLE_FP_EMULATION)
       "  .word emulate_float_store - illegal_insn_trap_table\n"
#else
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
#endif
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
#if !defined(__riscv_muldiv)
       "  .word emulate_mul_div - illegal_insn_trap_table\n"
#else
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
#endif
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
#if !defined(__riscv_muldiv) && __riscv_xlen >= 64
       "  .word emulate_mul_div32 - illegal_insn_trap_table\n"
#else
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
#endif
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
#ifdef PK_ENABLE_FP_EMULATION
       "  .word emulate_fmadd - illegal_insn_trap_table\n"
       "  .word emulate_fmadd - illegal_insn_trap_table\n"
       "  .word emulate_fmadd - illegal_insn_trap_table\n"
       "  .word emulate_fmadd - illegal_insn_trap_table\n"
       "  .word emulate_fp - illegal_insn_trap_table\n"
#else
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
#endif
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
       "  .word emulate_system_opcode - illegal_insn_trap_table\n"
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
       "  .word tag_trap - illegal_insn_trap_table\n"
       "  .word truly_illegal_insn - illegal_insn_trap_table\n"
       "  .popsection");
   
  uintptr_t mstatus = read_csr(mstatus);
  insn_t insn = read_csr(mbadaddr);

  if (unlikely((insn & 3) != 3)) {
    if (insn == 0)
      insn = get_insn(mepc, &mstatus);
    if ((insn & 3) != 3)
      return emulate_rvc(regs, mcause, mepc, mstatus, insn);
  }

  write_csr(mepc, mepc + 4);

  extern uint32_t illegal_insn_trap_table[];
  int32_t* pf = (void*)illegal_insn_trap_table + (insn & 0x7c);
  //printm("[IIT] addr of illegal_insn_trap_table: %x  (+ %x)\n", illegal_insn_trap_table, (insn & 0x7c));
  //printm("[IIT] calling illegal_insn_trap_table[%d]...\n", *pf);
  emulation_func f = (emulation_func)((void*)illegal_insn_trap_table + *pf);
  f(regs, mcause, mepc, mstatus, insn);
}

__attribute__((noinline))
DECLARE_EMULATION_FUNC(truly_illegal_insn)
{
  printm("TRULY ILLEGAL\n");
  printtag_debug("tag_trap. regs = %x. insn = %x. mcause = %lx. mepc = %lx. mstatus = %x.\n", regs, insn, mcause, mepc, mstatus);
  printregs((sm_thread_regs_t*) regs);
  return redirect_trap(mepc, mstatus, insn);
}

static inline int emulate_read_csr(int num, uintptr_t mstatus, uintptr_t* result)
{
  uintptr_t counteren = -1;
  if (EXTRACT_FIELD(mstatus, MSTATUS_MPP) == PRV_U)
    counteren = read_csr(scounteren);

  switch (num)
  {
    case CSR_CYCLE:
      if (!((counteren >> (CSR_CYCLE - CSR_CYCLE)) & 1))
        return -1;
      *result = read_csr(mcycle);
      return 0;
    case CSR_TIME:
      if (!((counteren >> (CSR_TIME - CSR_CYCLE)) & 1))
        return -1;
      *result = *mtime;
      return 0;
    case CSR_INSTRET:
      if (!((counteren >> (CSR_INSTRET - CSR_CYCLE)) & 1))
        return -1;
      *result = read_csr(minstret);
      return 0;
    case CSR_MHPMCOUNTER3:
      if (!((counteren >> (3 + CSR_MHPMCOUNTER3 - CSR_MHPMCOUNTER3)) & 1))
        return -1;
      *result = read_csr(mhpmcounter3);
      return 0;
    case CSR_MHPMCOUNTER4:
      if (!((counteren >> (3 + CSR_MHPMCOUNTER4 - CSR_MHPMCOUNTER3)) & 1))
        return -1;
      *result = read_csr(mhpmcounter4);
      return 0;
#if __riscv_xlen == 32
    case CSR_CYCLEH:
      if (!((counteren >> (CSR_CYCLE - CSR_CYCLE)) & 1))
        return -1;
      *result = read_csr(mcycleh);
      return 0;
    case CSR_TIMEH:
      if (!((counteren >> (CSR_TIME - CSR_CYCLE)) & 1))
        return -1;
      *result = *mtime >> 32;
      return 0;
    case CSR_INSTRETH:
      if (!((counteren >> (CSR_INSTRET - CSR_CYCLE)) & 1))
        return -1;
      *result = read_csr(minstreth);
      return 0;
    case CSR_MHPMCOUNTER3H:
      if (!((counteren >> (3 + CSR_MHPMCOUNTER3 - CSR_MHPMCOUNTER3)) & 1))
        return -1;
      *result = read_csr(mhpmcounter3h);
      return 0;
    case CSR_MHPMCOUNTER4H:
      if (!((counteren >> (3 + CSR_MHPMCOUNTER4 - CSR_MHPMCOUNTER3)) & 1))
        return -1;
      *result = read_csr(mhpmcounter4h);
      return 0;
#endif
    case CSR_MHPMEVENT3:
      *result = read_csr(mhpmevent3);
      return 0;
    case CSR_MHPMEVENT4:
      *result = read_csr(mhpmevent4);
      return 0;
#if !defined(__riscv_flen) && defined(PK_ENABLE_FP_EMULATION)
    case CSR_FRM:
      if ((mstatus & MSTATUS_FS) == 0) break;
      *result = GET_FRM();
      return 0;
    case CSR_FFLAGS:
      if ((mstatus & MSTATUS_FS) == 0) break;
      *result = GET_FFLAGS();
      return 0;
    case CSR_FCSR:
      if ((mstatus & MSTATUS_FS) == 0) break;
      *result = GET_FCSR();
      return 0;
#endif
  }
  return -1;
}

static inline int emulate_write_csr(int num, uintptr_t value, uintptr_t mstatus)
{
  switch (num)
  {
    case CSR_CYCLE: write_csr(mcycle, value); return 0;
    case CSR_INSTRET: write_csr(minstret, value); return 0;
    case CSR_MHPMCOUNTER3: write_csr(mhpmcounter3, value); return 0;
    case CSR_MHPMCOUNTER4: write_csr(mhpmcounter4, value); return 0;
#if __riscv_xlen == 32
    case CSR_CYCLEH: write_csr(mcycleh, value); return 0;
    case CSR_INSTRETH: write_csr(minstreth, value); return 0;
    case CSR_MHPMCOUNTER3H: write_csr(mhpmcounter3h, value); return 0;
    case CSR_MHPMCOUNTER4H: write_csr(mhpmcounter4h, value); return 0;
#endif
    case CSR_MHPMEVENT3: write_csr(mhpmevent3, value); return 0;
    case CSR_MHPMEVENT4: write_csr(mhpmevent4, value); return 0;
#if !defined(__riscv_flen) && defined(PK_ENABLE_FP_EMULATION)
    case CSR_FRM: SET_FRM(value); return 0;
    case CSR_FFLAGS: SET_FFLAGS(value); return 0;
    case CSR_FCSR: SET_FCSR(value); return 0;
#endif
  }
  return -1;
}

DECLARE_EMULATION_FUNC(emulate_system_opcode)
{
  int rs1_num = (insn >> 15) & 0x1f;
  uintptr_t rs1_val = GET_RS1(insn, regs);
  int csr_num = (uint32_t)insn >> 20;
  uintptr_t csr_val, new_csr_val;

  if (emulate_read_csr(csr_num, mstatus, &csr_val))
    return truly_illegal_insn(regs, mcause, mepc, mstatus, insn);

  int do_write = rs1_num;
  switch (GET_RM(insn))
  {
    case 0: return truly_illegal_insn(regs, mcause, mepc, mstatus, insn);
    case 1: new_csr_val = rs1_val; do_write = 1; break;
    case 2: new_csr_val = csr_val | rs1_val; break;
    case 3: new_csr_val = csr_val & ~rs1_val; break;
    case 4: return truly_illegal_insn(regs, mcause, mepc, mstatus, insn);
    case 5: new_csr_val = rs1_num; do_write = 1; break;
    case 6: new_csr_val = csr_val | rs1_num; break;
    case 7: new_csr_val = csr_val & ~rs1_num; break;
    default: new_csr_val = 0; // why do we do this?
  }

  if (do_write && emulate_write_csr(csr_num, new_csr_val, mstatus))
    return truly_illegal_insn(regs, mcause, mepc, mstatus, insn);

  SET_RD(insn, regs, csr_val);
}

DECLARE_EMULATION_FUNC(tag_trap)
{
  //printtag_debug("tag_trap. regs = %x. insn = %x. mcause = %x. mepc = %x. mstatus = %x.\n",
  //  regs, insn, mcause, mepc, mstatus);

  trap_m_call(regs, insn, mcause, mepc, mstatus);

  /*
  assert(mcause == 2);
  

  if ((insn & MASK_LTAG) == MATCH_LTAG)
  {
      trap_ltag((sm_thread_regs_t*)regs, mcause, mepc, mstatus, insn);
  }
  if ((insn & MASK_STAG) == MATCH_STAG)
  {
      trap_stag((sm_thread_regs_t*) regs, mcause, mepc, mstatus, insn);
  }
  if ((insn & MASK_PPAGE) == MATCH_PPAGE)
  {
      trap_ppage((sm_thread_regs_t*)regs, mcause, mepc, mstatus, insn); 
  }
  //sm_thread_regs_t* regs_ = (sm_thread_regs_t*) regs;
  //printtag_debug("a0 %lx a1 %lx a2 %lx a3 %lx a4 %lx a5 %lx a6 %lx a7 %lx\n", regs_->a0, regs_->a1, regs_->a2, regs_->a3, regs_->a4, regs_->a5, regs_->a6, regs_->a7);
  */
  //printtag_debug("tag_trap end\n");
}
