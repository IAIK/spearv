

#define PTE_MSB_SHIFT 54
#define PTE_MSB (0x3FFULL << PTE_MSB_SHIFT)

static inline const char * _irq_to_str(uintptr_t mcause){
    const char * result;
    switch (mcause)
    {
        case IRQ_U_SOFT:    result = "IRQ_U_SOFT"; break;
        case IRQ_S_SOFT:    result = "IRQ_S_SOFT"; break;
        case IRQ_VS_SOFT:   result = "IRQ_VS_SOFT"; break;
        case IRQ_M_SOFT:    result = "IRQ_M_SOFT"; break;
        case IRQ_U_TIMER:   result = "IRQ_U_TIMER"; break;
        case IRQ_S_TIMER:   result = "IRQ_S_TIMER"; break;
        case IRQ_VS_TIMER:  result = "IRQ_VS_TIMER"; break;
        case IRQ_M_TIMER:   result = "IRQ_M_TIMER"; break;
        case IRQ_U_EXT:     result = "IRQ_U_EXT"; break;
        case IRQ_S_EXT:     result = "IRQ_S_EXT"; break;
        case IRQ_VS_EXT:    result = "IRQ_VS_EXT"; break;
        case IRQ_M_EXT:     result = "IRQ_M_EXT"; break;
        case IRQ_S_GEXT:    result = "IRQ_S_GEXT"; break;
        //case IRQ_COP:       result = "IRQ_COP"; break;
        case IRQ_HOST:      result = "IRQ_HOST"; break;
        default:            result = "_UNKNOWN_"; break;
    }
    return result;
}


static const char* _cause_to_str(unsigned long mcause)
{
    unsigned long mcause_highest_bit_cleared = mcause & (((unsigned long)1<<63) - 1);
    if(mcause != mcause_highest_bit_cleared){
        return _irq_to_str(mcause_highest_bit_cleared);
    }

    const char* cause = "???";
    switch(mcause) {
    #define DECLARE_CAUSE(name, causeid) case causeid: cause = #name; break;
    #include "encoding.h"
    #undef DECLARE_CAUSE
    default:
        break;
    };
    return cause;
}


static const char * tagmode_to_str(TagMode mode){
    const char *         ret = "???"   ;
    if(mode == MTAG0)    ret = "MTAG0  ";
    if(mode == MTAG32)   ret = "MTAG32 ";
    if(mode == MTAG64)   ret = "MTAG64 ";
    if(mode == MTAG128)  ret = "MTAG128";
    return ret;
}

static const char * pagetype_to_str(PageType pt){
    const char * ret = "";
    if(pt == PT_NORMAL)    ret = "PT_NORMAL   ";
    if(pt == PT_ENCLAVE)   ret = "PT_ENCLAVE  ";
    if(pt == PT_MONITOR)   ret = "PT_MONITOR  ";
    if(pt == PT_PAGETABLE) ret = "PT_PAGETABLE";
    return ret;
}

static const char * pagelevel_to_str(PageLevel pl){
    const char * ret = "????";
    if(pl == PL_KILO)    ret = "4KiB";
    if(pl == PL_MEGA)    ret = "2MiB";
    if(pl == PL_GIGA)    ret = "2GiB";
    return ret;
}

#ifndef SPIKE
inline static uint64_t SATPtoPPN(uint64_t satp){
    return satp & SATP64_PPN;
}
inline static uint64_t SATPtoDepth(uint64_t satp){
    uint64_t mode = (satp & SATP64_MODE) >> 60;
    uint64_t depth = 0;
    if (mode == SATP_MODE_SV39) {
        depth = 2;
    } else if (mode == SATP_MODE_SV48) {
        depth = 3;
    } else {
        assert(0);
    }
    return depth;
}
inline static void printSATP(uint64_t satp){
    uint64_t mode = (satp & SATP64_MODE) >> 60;
    uint64_t asid = (satp & SATP64_ASID) >> 44;
    uint64_t ppn  = (satp & SATP64_PPN)  >>  0;

    const char * mode_str = "";
    if(mode == SATP_MODE_OFF)  mode_str = "SATP_MODE_OFF ";
    if(mode == SATP_MODE_SV32) mode_str = "SATP_MODE_SV32";
    if(mode == SATP_MODE_SV39) mode_str = "SATP_MODE_SV39";
    if(mode == SATP_MODE_SV48) mode_str = "SATP_MODE_SV48";
    if(mode == SATP_MODE_SV57) mode_str = "SATP_MODE_SV57";
    if(mode == SATP_MODE_SV64) mode_str = "SATP_MODE_SV64";

    printtag_debug("mode %s", mode_str);
    printtag_debug2(" | asid 0x%4x", (uint32_t)asid);
    printtag_debug2(" | ppn 0x%8lx", ppn);
    // printtag_debug2(" | satp 0x%16lx ", satp);
    printtag_debug2("\n");
}

inline static void printregs(sm_thread_regs_t* reg_state)
{
    printtag_debug("ra  = %lx ", reg_state->ra);
    printtag_debug2("sp  = %lx ", reg_state->sp);
    printtag_debug2("gp  = %lx ", reg_state->gp);
    printtag_debug2("tp  = %lx ", reg_state->tp);
    printtag_debug2("\n");
    printtag_debug("t0  = %lx ", reg_state->t0);
    printtag_debug2("t1  = %lx ", reg_state->t1);
    printtag_debug2("t2  = %lx ", reg_state->t2);
    printtag_debug2("s0  = %lx ", reg_state->s0);
    printtag_debug2("\n");
    printtag_debug("s1  = %lx ", reg_state->s1);
    printtag_debug2("a0  = %lx ", reg_state->a0);
    printtag_debug2("a1  = %lx ", reg_state->a1);
    printtag_debug2("a2  = %lx ", reg_state->a2);
    printtag_debug2("\n");
    printtag_debug("a3  = %lx ", reg_state->a3);
    printtag_debug2("a4  = %lx ", reg_state->a4);
    printtag_debug2("a5  = %lx ", reg_state->a5);
    printtag_debug2("a6  = %lx ", reg_state->a6);
    printtag_debug2("\n");
    printtag_debug("a7  = %lx ", reg_state->a7);
    printtag_debug2("s2  = %lx ", reg_state->s2);
    printtag_debug2("s3  = %lx ", reg_state->s3);
    printtag_debug2("s4  = %lx ", reg_state->s4);
    printtag_debug2("\n");
    printtag_debug("s5  = %lx ", reg_state->s5);
    printtag_debug2("s6  = %lx ", reg_state->s6);
    printtag_debug2("s7  = %lx ", reg_state->s7);
    printtag_debug2("s8  = %lx ", reg_state->s8);
    printtag_debug2("\n");
    printtag_debug("s9  = %lx ", reg_state->s9);
    printtag_debug2("s10 = %lx ", reg_state->s10);
    printtag_debug2("s11 = %lx ", reg_state->s11);
    printtag_debug2("t3  = %lx ", reg_state->t3);
    printtag_debug2("\n");
    printtag_debug("t4  = %lx ", reg_state->t4);
    printtag_debug2("t5  = %lx ", reg_state->t5);
    printtag_debug2("t6  = %lx ", reg_state->t6);
    printtag_debug2("\n");
}


inline static void printMIP(uintptr_t mip)
{
    printtag_debug_interrupt("MIP = ");
    printtag_debug_interrupt2("%s%s%s ", mip & MIP_SGEIP ? COLOR_GREEN : COLOR_RED, "SGEIP", COLOR_RESET);
    printtag_debug_interrupt2("%s%s%s ", mip & MIP_MEIP  ? COLOR_GREEN : COLOR_RED, "MEIP" , COLOR_RESET);
    printtag_debug_interrupt2("%s%s%s ", mip & MIP_VSEIP ? COLOR_GREEN : COLOR_RED, "VSEIP", COLOR_RESET);
    printtag_debug_interrupt2("%s%s%s ", mip & MIP_SEIP  ? COLOR_GREEN : COLOR_RED, "SEIP" , COLOR_RESET);
    printtag_debug_interrupt2("%s%s%s ", mip & MIP_MTIP  ? COLOR_GREEN : COLOR_RED, "MTIP" , COLOR_RESET);
    printtag_debug_interrupt2("%s%s%s ", mip & MIP_VSTIP ? COLOR_GREEN : COLOR_RED, "VSTIP", COLOR_RESET);
    printtag_debug_interrupt2("%s%s%s ", mip & MIP_STIP  ? COLOR_GREEN : COLOR_RED, "STIP" , COLOR_RESET);
    printtag_debug_interrupt2("%s%s%s ", mip & MIP_MSIP  ? COLOR_GREEN : COLOR_RED, "MSIP" , COLOR_RESET);
    printtag_debug_interrupt2("%s%s%s ", mip & MIP_VSSIP ? COLOR_GREEN : COLOR_RED, "VSSIP", COLOR_RESET);
    printtag_debug_interrupt2("%s%s%s ", mip & MIP_SSIP  ? COLOR_GREEN : COLOR_RED, "SSIP" , COLOR_RESET);
    printtag_debug_interrupt2("\n");
}
#endif

#define printTagGeneric(tag, PRINT_FUNCTION) do { \
        PRINT_FUNCTION("%sid 0x%x%s", (tag)->bit.id         ? COLOR_GREEN : COLOR_GRAY, (tag)->bit.id, COLOR_RESET); \
        PRINT_FUNCTION(" %s|%s ", COLOR_CYAN, COLOR_RESET); \
        PRINT_FUNCTION("%s%s%s ",        (tag)->bit.page_level ? COLOR_GREEN : COLOR_GRAY, pagelevel_to_str((tag)->bit.page_level), COLOR_RESET); \
        PRINT_FUNCTION("%s%s%s ",        (tag)->bit.page_type  ? COLOR_GREEN : COLOR_GRAY, pagetype_to_str((tag)->bit.page_type), COLOR_RESET); \
        \
        PRINT_FUNCTION("%s",            (tag)->bit.immutable  ? COLOR_GREEN "I" COLOR_RESET : COLOR_RED "I" COLOR_RESET); \
        PRINT_FUNCTION("%s",            (tag)->bit.validated  ? COLOR_GREEN "V" COLOR_RESET : COLOR_RED "V" COLOR_RESET); \
        PRINT_FUNCTION("%s ",           (tag)->bit.hpce       ? COLOR_GREEN "H" COLOR_RESET : COLOR_RED "H" COLOR_RESET); \
        \
        /*if(mode == MTAG64 || mode == MTAG128){*/ \
        /*PRINT_FUNCTION("%s", ((tag)->bit.pte_perms << 1) & PTE_G ? COLOR_GREEN "G" COLOR_RESET : COLOR_RED "G" COLOR_RESET);*/ \
        PRINT_FUNCTION("%s", ((tag)->bit.pte_perms << 1) & PTE_U ? COLOR_GREEN "U" COLOR_RESET : COLOR_RED "U" COLOR_RESET); \
        PRINT_FUNCTION("%s", ((tag)->bit.pte_perms << 1) & PTE_X ? COLOR_GREEN "X" COLOR_RESET : COLOR_RED "X" COLOR_RESET); \
        PRINT_FUNCTION("%s", ((tag)->bit.pte_perms << 1) & PTE_W ? COLOR_GREEN "W" COLOR_RESET : COLOR_RED "W" COLOR_RESET); \
        PRINT_FUNCTION("%s", ((tag)->bit.pte_perms << 1) & PTE_R ? COLOR_GREEN "R" COLOR_RESET : COLOR_RED "R" COLOR_RESET); \
        \
        if((tag)->bit.vpn < (uint64_t)1<<32){ \
            PRINT_FUNCTION(" | %svpn 0x%x", (tag)->bit.vpn ? COLOR_GREEN : COLOR_GRAY, (uint32_t)(tag)->bit.vpn); \
        }else{ \
            PRINT_FUNCTION(" | %svpn 0x%lx", (tag)->bit.vpn ? COLOR_GREEN : COLOR_GRAY, (tag)->bit.vpn); \
        } \
        /*PRINT_FUNCTION(" | %s0x%x%s",  (tag)->bit.mpk        ? COLOR_GREEN : COLOR_GRAY, (tag)->bit.mpk, COLOR_RESET);*/ \
        /*}*/ \
        /*if(mode == MTAG128){*/ \
        /*PRINT_FUNCTION("%s 0x%lx ", (tag)->bit.unused ? COLOR_GREEN : COLOR_GRAY, (tag)->bit.unused);*/ \
        /*PRINT_FUNCTION(" | %sunused 0x%lx", (tag)->bit.unused ? COLOR_GREEN : COLOR_GRAY, (tag)->bit.unused);*/ \
        /*}*/ \
    } while (0)

#ifndef SPIKE

inline static void printTag(union memory_tag* tag /*, uint8_t mode*/){
    printTagGeneric(tag, printtag_debug2 /*, mode*/);
}

inline static void printTagControl(uintptr_t tag_control)
{
    printtag_debug("%s%s%s | %s%s%s | %s%s%s | %s%s%s\n",
        (tag_control & TAG_CTRL_DISABLE_IMM_PT_CHECKS     ) ? COLOR_GREEN : COLOR_RED, "IMM_PT",      COLOR_RESET,
        (tag_control & TAG_CTRL_DISABLE_TAG_COMPARE_CHECKS) ? COLOR_GREEN : COLOR_RED, "TAG_COMPARE", COLOR_RESET,
        (tag_control & TAG_CTRL_NC_PTW_IN_E               ) ? COLOR_GREEN : COLOR_RED, "NC_PTW_IN_E", COLOR_RESET,
        (tag_control & TAG_CTRL_DISABLE_IMM_WRITE_CHECK   ) ? COLOR_GREEN : COLOR_RED, "IMM_WRITE"  , COLOR_RESET
        );
}

inline static void printPTE(uint64_t pte, int print_tag, int16_t depth){
    uint64_t ppn        = (pte & ~(PTE_MSB)) >> PTE_PPN_SHIFT;
    //printtag_debug("");
    if(ppn < (uint64_t)1<<32){
        printtag_debug2(COLOR_GRAY "[ 0x%x | ", (uint32_t)ppn);
    }else{
        printtag_debug2(COLOR_GRAY "[ 0x%lx | ", ppn);
    }

    printtag_debug2("%s", pte & PTE_D ? COLOR_GREEN "D" COLOR_RESET : COLOR_RED "D" COLOR_RESET);
    printtag_debug2("%s", pte & PTE_A ? COLOR_GREEN "A" COLOR_RESET : COLOR_RED "A" COLOR_RESET);
    printtag_debug2("%s", pte & PTE_G ? COLOR_GREEN "G" COLOR_RESET : COLOR_RED "G" COLOR_RESET);
    printtag_debug2("%s", pte & PTE_U ? COLOR_GREEN "U" COLOR_RESET : COLOR_RED "U" COLOR_RESET);
    printtag_debug2("%s", pte & PTE_X ? COLOR_GREEN "X" COLOR_RESET : COLOR_RED "X" COLOR_RESET);
    printtag_debug2("%s", pte & PTE_W ? COLOR_GREEN "W" COLOR_RESET : COLOR_RED "W" COLOR_RESET);
    printtag_debug2("%s", pte & PTE_R ? COLOR_GREEN "R" COLOR_RESET : COLOR_RED "R" COLOR_RESET);
    printtag_debug2("%s", pte & PTE_V ? COLOR_GREEN "V" COLOR_RESET : COLOR_RED "V" COLOR_RESET);

    printtag_debug2(" %s", PTE_TABLE(pte) ? COLOR_MAGENTA "PTE" COLOR_RESET : COLOR_YELLOW "LEAF" COLOR_RESET);
    if(depth != -1){
        if(!PTE_TABLE(pte)){
            printtag_debug2("(" COLOR_YELLOW "%s", pagelevel_to_str(depth));
            printtag_debug2(")");
        }else{
            printtag_debug2("(" COLOR_MAGENTA "%d", depth);
            printtag_debug2(")    ");
        }
    }
    printtag_debug2(COLOR_GRAY "]" COLOR_RESET);

    //printtag_debug2("pte 0x%16lx", pte);

    if(print_tag && pte & PTE_V){
        printtag_debug2(" Tag: ");
        union memory_tag tag;
        if(read_tag(&tag, ppn)){
            printtag_debug2("[");
            printTag(&tag);
            printtag_debug2("]");
        }else{
            printtag_debug2("[ untagged memory ]");
        }
    }

    printtag_debug2("\n");
}
#endif

