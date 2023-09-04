
//------------------------------------------------------------------------------
//fence.t from:
//    https://arxiv.org/pdf/2005.02193.pdf
//    https://github.com/niwis/ariane/tree/fence-t
//    https://github.com/niwis/channel-bench/tree/riscv
#define FLUSH_NONE               (0)
#define FLUSH_ENABLE             (1 << 14)
#define FLUSH_ALL                ((0xFFFFF) | FLUSH_ENABLE)
#define FLUSH_IF                 ((1 <<  0) | FLUSH_ENABLE)
#define FLUSH_UNISSUED_INSTR     ((1 <<  1) | FLUSH_ENABLE)
#define FLUSH_ID                 ((1 <<  2) | FLUSH_ENABLE)
#define FLUSH_EX                 ((1 <<  3) | FLUSH_ENABLE)
#define FLUSH_DCACHE             ((1 <<  4) | FLUSH_ENABLE)
#define FLUSH_ICACHE             ((1 <<  5) | FLUSH_ENABLE)
#define FLUSH_TLB                ((1 <<  6) | FLUSH_ENABLE)
#define FLUSH_BP                 ((1 <<  7) | FLUSH_ENABLE)
#define FLUSH_DCACHE_LFSR        ((1 <<  8) | FLUSH_ENABLE)
#define FLUSH_ICACHE_LFSR        ((1 <<  9) | FLUSH_ENABLE)
#define FLUSH_TLB_PLRU_TREE      ((1 << 10) | FLUSH_ENABLE)
#define FLUSH_DCACHE_MEM_ARB     ((1 << 11) | FLUSH_ENABLE)
#define FLUSH_DCACHE_WBUFFER_ARB ((1 << 12) | FLUSH_ENABLE)
#define FLUSH_DCACHE_FIFO        ((1 << 13) | FLUSH_ENABLE)


#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define UTYPE(imm20, rd, opcode) (((imm20 & 0xFFFFF) << 12) | ((rd & 0x1F) << 7) | ((opcode & 0x7F) << 0))
#define FENCE_T(imm20) ".word " TOSTRING(UTYPE(imm20, 0, 0xB)) ";"
#define fence_t(val) ({ asm volatile( FENCE_T(val) ); })
//Note: implementation uses OpcodeCustom0, which is defined as 0xB with mask 0x7f
//------------------------------------------------------------------------------

//TODO flush all cores if multicore

extern bool flush_entire_tlb_for_this_core_at_exit;
extern bool use_fence_t;

inline void flush_microarchitectural_buffers(){
    if(use_fence_t){
        printtag_debug("fence_t\n");
        fence_t(0
            | FLUSH_IF                
            | FLUSH_UNISSUED_INSTR    
            | FLUSH_ID                
            | FLUSH_EX                
            | FLUSH_DCACHE            
            | FLUSH_ICACHE            
            | FLUSH_TLB               
            | FLUSH_BP                
            | FLUSH_DCACHE_LFSR       
            | FLUSH_ICACHE_LFSR       
            | FLUSH_TLB_PLRU_TREE     
            | FLUSH_DCACHE_MEM_ARB    
            | FLUSH_DCACHE_WBUFFER_ARB
            | FLUSH_DCACHE_FIFO       
        );
    }
}

inline void sfence_vma(uint64_t vaddr, uint64_t asid){
    asm volatile("sfence.vma %0, %1" : : "r"(vaddr), "r"(asid) );
}
inline void flush_tlb_this_core(){
    printtag_debug("Flushing TLB\n");
    //using fence.t instruction to ONLY flush TLB. because sfence.vma also does flush_if_o, flush_unissued_instr_o, flush_id_o, flush_ex_o, which is done anyway at exception-return.
    //TODO verify that fence_t(FLUSH_TLB) works, then remove sfence.vma and only use fence_t(FLUSH_TLB)
    // if(use_fence_t){
        // fence_t(FLUSH_TLB);
    // }else{
        // sfence_vma(0,0);
    // }
    sfence_vma(0,0);

    flush_entire_tlb_for_this_core_at_exit = false;
}

inline void flush_tlb_this_core_if_flush_pending(){
    if(flush_entire_tlb_for_this_core_at_exit){
        flush_tlb_this_core();
    }
}

inline void flush_tlb_ppn(uint64_t ppn){
    //if(!do_flush){
    //    return;
    //}
    //Note: we flush the entire TLB for now.
    // just flushing when ASID=MEID is not enough, since other mappings may still existfor now we flush TLB entries if the ASID matches
    // this results in less of a performance hit than flushing the entire TLB.
    // technically flushing only the affected PPNs is better, but we expect 
    // that tag updates are not frequent anyway, so it does not matter a lot.
    flush_entire_tlb_for_this_core_at_exit = true;

    //TODO also flush other cores (see SFENCE IPI in mcall_trap)
}
