#include "tag.h"
#include "tag_debug.h"
#include "mtrap.h"
#include "atomic.h"
#include "emulation.h"
#include "pk.h"
#include "flush.h"

#define SM_INTERRUPT_HANDLING

extern void trap_vector();
extern void trap_vector_enclave();
extern void __attribute__((noreturn)) bad_trap(uintptr_t* regs, uintptr_t dummy, uintptr_t mepc);
static bool _va_range_to_enclave(uint64_t vaddr, uint64_t size, e_metapage* statuspage_pa, uint64_t mepc, bool prot, bool zero_mem);
bool ppn_is_mapped(uint64_t ppn_of_page_table, size_t depth, uint64_t current_vaddr, uint64_t ppn, uint64_t vaddr_to_ignore);

//------------------------------------------------------------------------------

bool flush_entire_tlb_for_this_core_at_exit;
bool use_fence_t = false;

bool debug_print_walk = 1;

//------------------------------------------------------------------------------
#define BITS_PER_WORD (sizeof(uint64_t) * 8)
#define BITMAP_WORDS (((uint64_t)1<<16) / BITS_PER_WORD )
uint64_t bitmap_eid[BITMAP_WORDS] = {0,};
#define BIT_OFFSET(b)  ((b) % BITS_PER_WORD)
static spinlock_t bitmap_eid_lock = SPINLOCK_INIT;
static spinlock_t tagstore_lock = SPINLOCK_INIT;

static uint64_t _allocate_eid(){
    spinlock_lock(&bitmap_eid_lock);
    for (size_t i = 0; i < BITMAP_WORDS; i++) {
        uint64_t * word = &(bitmap_eid[i]);
        if(*word != (uint64_t)-1){
            //free bits in word
            for (size_t bit = 0; bit < BITS_PER_WORD; bit++) {
                uint64_t bit_in_word = (uint64_t)1 << bit;
                if((*word & bit_in_word) == 0) {
                    uint64_t eid = i * BITS_PER_WORD + bit;
                    *word = *word | bit_in_word;
                    spinlock_unlock(&bitmap_eid_lock);
                    return eid;
                }
            }
        }
    }
    spinlock_unlock(&bitmap_eid_lock);
    return -1;
}
static inline void _deallocate_eid(uint64_t eid){
    assert(eid < ((uint64_t)1<<16));
    spinlock_lock(&bitmap_eid_lock);
    bitmap_eid[eid / BITS_PER_WORD] &= ~((uint64_t)1 << BIT_OFFSET(eid));
    spinlock_unlock(&bitmap_eid_lock);
}
static inline void _allocate_specific_eid(uint64_t eid){
    assert(eid < ((uint64_t)1<<16));
    spinlock_lock(&bitmap_eid_lock);
    bitmap_eid[eid / BITS_PER_WORD] |= ((uint64_t)1 << BIT_OFFSET(eid));
    spinlock_unlock(&bitmap_eid_lock);
}
static inline int _eid_exists(uint64_t eid){
    assert(eid < ((uint64_t)1<<16));
    spinlock_lock(&bitmap_eid_lock);
    int ret = !!(bitmap_eid[eid / BITS_PER_WORD] & ((uint64_t)1 << BIT_OFFSET(eid)));
    spinlock_unlock(&bitmap_eid_lock);
    return ret;
}
//------------------------------------------------------------------------------

//extern long do_flush_this_core = 0;
//extern long do_flush_other_cores;

//#define getASID() ( CSRR(CSR_SATP) & SATP64_ASID >> 44 )
//#define isValidPPN(ppn) ((ppn) >= mem_base && (ppn) < CSRR(CSR_U_TAG_STORAGE_BASE)>>RISCV_PGSHIFT)
//TODO global lock and lock per secs?


//TODO whenever we update the page_type or immutable bits, we must set the HPCE bits accordingly in all parent mega/giga tags. this also applies to the tagstore itself (mega/giga mapping may partially map the tagstore)


#define is_in_enclave() (CSRR(CSR_U_MEID) != 0)

void tag_enclave_init(){
    //set up global variables
    memset((void*)bitmap_eid, 0x00, BITMAP_WORDS * sizeof(*bitmap_eid));
    assert(_allocate_eid() == 0); //reserve 0th ID
    _allocate_specific_eid(EID_INVALID);
    assert(_eid_exists(EID_INVALID));
}

static inline bool emulate_sd_to_immutable_page(uintptr_t addr, uint64_t val, uintptr_t mepc, uint64_t* val_ret)
{
    printtag_debug("addr: 0x%lx\n", addr);
    printtag_debug("val:  0x%lx\n", val);

    union memory_tag tag = {0};
    uintptr_t ppn = getPPN4K(addr, mepc);
    VA va = {.raw = addr};
    uintptr_t pa = (ppn << 12) + va.fields.offset;
    read_tag(&tag, ppn);
    printtag_debug("tag: ["); printTag(&tag); printtag_debug2("].\n"); 

    //NOTE: i think this check here is the only reason we tag the page as PT_PAGETABLE
    if(tag.bit.immutable && tag.bit.page_type == PT_PAGETABLE){
        printtag_debug("emulate SD to pagetable\n");

        if (unlikely(addr % sizeof(uintptr_t))){
            printtag_error("Misaligned store really shouldnt happen when writing PTEs\n");
            return false;
        }

        printtag_debug("PA = 0x%x\n", pa);

        printtag_debug("PA = 0x%x\n", pa);
        PTE_64_Union old = {.raw_value = *(uint64_t*)pa};
        PTE_64_Union new = {.raw_value = val};
        printtag_debug("old: "); printPTE(old.raw_value, 1, -1);
        printtag_debug("new: "); printPTE(new.raw_value, 1, -1);

        if(!(old.raw_value & PTE_V)){
            //existing PTE is not valid
            goto emulate_write;
        }else{
            //already existing valid PTE
            //check tag:
            union memory_tag tag_child = {0};
            read_tag(&tag_child, old.pte.ppn);
            //note: we dont know the depth for this PTE here, so we have to assume that we correctly tagged all 4k pages if this (old.pte.ppn) would point to a larger page
            if(!tag_child.bit.immutable){
                goto emulate_write;
            }else{
                printtag_error("Existing PTE already points to immutable page.\n");
                return false;
            }
        }
        return false;
    }else{
        printtag_error("tag is not immutable and/or pagetype is not pagetable.\n");
        return false;
    }
    return false;

emulate_write:
    *val_ret = val;
    printtag_debug("Emulating write to immutable page.\n");
    *(uint64_t*)pa = val;
    //TODO evict affected cacheline?
    return true;
}

//------------------------------------------------------------------------------
void enclave_access_trap(uintptr_t* regs, uintptr_t mcause, uintptr_t mepc){
    printtag_debug("ENCLAVE ACCESS FAULT: Probably store to immutable page.\n");
    uintptr_t mstatus;
    insn_t insn = get_insn(mepc, &mstatus); // this also reads mstatus csr
    uintptr_t npc = mepc + insn_len(insn);
    uintptr_t addr = read_csr(mbadaddr);

    if(EXTRACT_FIELD(mstatus, MSTATUS_MPP) == PRV_U){
        printtag_error("PRV_U tried to do something.\n");
        goto not_implemented;
    }
    
    uint8_t amoswap = 0;
    //assert(EXTRACT_FIELD(mstatus, MSTATUS_MPP) == PRV_S);
    uintptr_t val;
    uint64_t val_ret;
    if ((insn & MASK_C_SD) == MATCH_C_SD){
        //addr = GET_RS1S(insn, regs) + RVC_LD_IMM(insn);
        val = GET_RS2S(insn, regs);
        goto emulate_sd;
    } else if ((insn & MASK_SD) == MATCH_SD){
        val = GET_RS2(insn, regs);
        goto emulate_sd;
    } else if ((insn & MASK_AMOSWAP_D) == MATCH_AMOSWAP_D) {
        //printtag_debug("AMOSWAP insn\n");
        amoswap = 1;
        addr = GET_RS1(insn, regs);
        val = GET_RS2(insn, regs);
        //printtag_debug("addr = %p   val = 0x%lx\n", addr, val);
        //printregs((sm_thread_regs_t*)regs);
        SET_RD(insn, regs, val);
        goto emulate_sd;
    } else {
        printtag_error("Unsupported instruction: 0x%x\n", insn);
not_implemented:
        printtag_error("addr: %p\n", addr);
        uintptr_t ppn = getPPN4K(addr, mepc);
        VA va = {.raw = addr};
        uintptr_t pa = (ppn << 12) + va.fields.offset;
        union memory_tag tag = {0};
        read_tag(&tag, ppn);
        printtag_debug("tag: ["); printTag(&tag); printtag_debug2("].\n"); 
        printtag_error("Not implemented\n");
        bad_trap(regs, mcause, mepc);
        assert(0);
    }
emulate_sd:
    if(emulate_sd_to_immutable_page(addr, val, mepc, &val_ret)){
        if (amoswap)
            *GET_REG(insn, SH_RS2, regs) = val_ret;
        goto end;
    }else{
        goto not_implemented;
    }

end:
    write_csr(mepc, npc);
    printtag_debug("Emulated store\n");
    flush_tlb_this_core_if_flush_pending();
}

void hpce_trap(uintptr_t* regs, uintptr_t mcause, uintptr_t mepc)
{
    printtag_warning("Tried accessing huge page containing enclave\n");
    uintptr_t addr = read_csr(mbadaddr);
    printtag_warning("mepc = %p\n", mepc);
    printtag_warning("addr = %p\n", addr);

    // TODO: pass pagefault to supervisor
#if DEBUG_TAG == 1
    union memory_tag tag = {0};
    uintptr_t ppn_mepc = getPPN4K(addr, mepc);
    uintptr_t ppn_mega = ppn_mepc & ~(0x1ffull);
    //TODO GIGA, etc
    for (uintptr_t ppn = ppn_mega; ppn < ppn_mega+512; ppn++)
    {
        read_tag(&tag, ppn);
        if(tag.direct64[0] || tag.direct64[1])
        {
            printtag_debug("==> Tag within huge page for ppn %x: [", ppn); printTag(&tag); printtag_debug2("]\n");
        }
    }
#endif
    printtag_warning("TODO let OS know that it cannot have a huge page mapping here\n");
    bad_trap(regs, mcause, mepc);
    assert(0);
}


void trap_m_call(uintptr_t* _regs, insn_t insn, uintptr_t mcause, uintptr_t mepc, uintptr_t mstatus)
{
    sm_thread_regs_t* regs = (sm_thread_regs_t*)(_regs + 1);
    uint64_t api_number = regs->a0;
    //printtag_debug("trap_m_call(%x,%x,%x)\n", regs->a0, regs->a1, regs->a2);
    uint8_t mode = CSRR(CSR_U_TAG_MODE);
    
    if ((mode == MTAG0) && (api_number != TAGRESET)) {
        printtag_error("Cannot use enclaves while tagging is disabled. Failed API call: %d\n", api_number);
        regs->a0 = API_RET_FAILED;
        return;
    }

    switch(api_number)
    {
        case LTAG2:
            trap_ltag2(regs, mepc);
            // sets a0,a1
            break;
        case LTAG:
            regs->a0 = trap_ltag(regs, mepc);
            //a0 = tag
            break;
        case STAG:
            trap_stag(regs, mepc);
            regs->a0 = API_RET_SUCCESS;
            break;
        case PPAGE:
            trap_ppage(regs, mepc);
            regs->a0 = API_RET_SUCCESS;
            break;
        case ECREATE:
            trap_ecreate(regs, mepc);
            regs->a0 = API_RET_SUCCESS;
            break;
        case EENTER:
            trap_eenter(regs, mepc);
            //a0 must remain unchanged!
            break;
        case EEXIT:
            trap_eexit(regs, mepc);
            // sets a0,a1
            break;
        case EDESTROY:
            trap_edestroy(regs, mepc);
            regs->a0 = API_RET_SUCCESS;
            break;
        case EADD:
            trap_eadd(regs, mepc);
            regs->a0 = API_RET_SUCCESS;
            break;
        case EREMOVE:
            trap_eremove(regs, mepc);
            regs->a0 = API_RET_SUCCESS;
            break;
        case TAGRESET:
            trap_tagreset(regs, mepc);
            // sets a0 to the current mode
            break;
        case API_DEBUG:
            trap_debug(regs, mepc);
            regs->a0 = API_RET_SUCCESS;
            break;
        case API_SET_FENCE:
            trap_set_fence(regs, mepc);
            regs->a0 = API_RET_SUCCESS;
            break;
        default:
            assert(0);
    }
    flush_tlb_this_core_if_flush_pending();
}
//------------------------------------------------------------------------------

static inline void _clear_tag(union memory_tag* tag){
    tag->direct64[0] = 0ULL;
    tag->direct64[1] = 0ULL;
}

static bool _is_non_enclave_page(union memory_tag * tag, e_metapage* statuspage_pa){
    return (tag->bit.page_type == PT_NORMAL && tag->bit.id == 0);
}

static bool _belongs_to_this_enclave(union memory_tag * tag, e_metapage* statuspage_pa){
    if(!statuspage_pa){
        return true;
    }
    return (
        tag->bit.id        == statuspage_pa->id &&
        tag->bit.page_type == PT_ENCLAVE &&
        tag->bit.immutable == 0
    );
}

static void _tag_megapage(uint64_t ppn)
{
#if SM_TAG_MEGAPAGES == 0
    return;
#endif
    //TODO GIGAPAGE

    union memory_tag tmp;
    uint64_t megapage_ppn = ppn & ~(0x1ffull);
    read_tag(&tmp, megapage_ppn);
    printtag_debug("Tagging megapage ppn = 0x%lx (4k-ppn = 0x%lx)\n", megapage_ppn, ppn);
    printtag_debug("Tag for ppn %x: [", ppn); printTag(&tmp); printtag_debug2("]\n");
    // already tagged correctly 
    if (tmp.bit.hpce)
    {
        printtag_debug("...already tagged correctly\n");
    }
    else
    {
        printtag_debug("...setting hpce bit\n");
        tmp.bit.hpce = 1;
        write_tag(&tmp, megapage_ppn);
    }
}

// returns true if clear worked, false if clear isn't possible yet
static bool _clear_megapage_tag_unlocked(uint64_t mp_ppn, uint64_t eid)
{
#if SM_TAG_MEGAPAGES == 0
    return true;
#endif
    bool can_be_cleared = true;
    union memory_tag tag;
    for (size_t i = 0; i < 512; i++)
    {
        uint64_t check_ppn = mp_ppn + i;
        read_tag(&tag, check_ppn);
        if (tag.bit.id != 0 /*&& tag.bit.id != eid*/ // different enclave page
         || tag.bit.page_type == PT_MONITOR // monitor page
         || tag.bit.page_type == PT_ENCLAVE // enclave page
         //TODO check for immutability bit as well
        )
        {
            can_be_cleared = false;
        }
    }
    if (can_be_cleared)
    {
        read_tag(&tag, mp_ppn);
        tag.bit.hpce = 0;
        write_tag(&tag, mp_ppn);
        spinlock_unlock(&tagstore_lock);
        return true;
    }
    return false;
}

static bool _make_enclave_page_unlocked(uint64_t vpn, uint64_t ppn, uint16_t depth, uint8_t permissions, e_metapage* statuspage_pa, bool dry_run, bool tag_megapage)
{
    union memory_tag tmp;
    bool tag_valid = read_tag(&tmp, ppn);
    if(!tag_valid){
        printtag_error("page not taggable. (VPN 0x%x, PPN 0x%x)\n", vpn, ppn);
        return false;
    }
    if(!_is_non_enclave_page(&tmp, statuspage_pa)){
        printtag_error("page is not available.\n");
        return false;
    }
    if(dry_run){
        return true;
    }
    tmp.bit.id          = statuspage_pa->id;
    tmp.bit.vpn         = vpn;
    tmp.bit.page_level  = depth;
    tmp.bit.page_type   = PT_ENCLAVE;
    tmp.bit.pte_perms   = permissions & 0xf; //we only store UXWR (but we might get GUXWR because legacy)
    //tmp.bit.validated
    write_tag(&tmp, ppn);
    statuspage_pa->mapped_pages++;
    if(tag_megapage){
        _tag_megapage(ppn);
    }
    return true;
}

static bool _destroy_enclave_page_unlocked(uint64_t vpn, uint64_t ppn, uint16_t depth, e_metapage* statuspage_pa, bool wipe, bool dry_run)
{
    union memory_tag tmp;
    read_tag(&tmp, ppn);
    if(!_belongs_to_this_enclave(&tmp, statuspage_pa)){
        printtag_error("page does not belong to this enclave.\n");
        printtag_error("VPN 0x%x\n", vpn);
        printtag_error("PPN 0x%x\n", ppn);
        return false;
    }
    if(dry_run){
        goto end_success;
    }
    tmp.bit.id          = 0;
    tmp.bit.vpn         = 0;
    tmp.bit.page_level  = 0;
    tmp.bit.page_type   = PT_NORMAL;
    tmp.bit.pte_perms   = 0;
    //tmp.bit.validated
    if(!statuspage_pa){
        tmp.bit.immutable = 0;
    }

    if(statuspage_pa){
        statuspage_pa->mapped_pages--;
    }
    if(wipe){
        fast_memset((char*)(ppn << RISCV_PGSHIFT), 0, RISCV_PGSIZE); //wipe page before making it globally accessible
    }

    write_tag(&tmp, ppn);

end_success:
    return true;
}

static bool _va_range_remove_from_enclave(uint64_t vaddr, uint64_t size, e_metapage* statuspage_pa, uint64_t mepc, bool wipe, uint64_t eid, bool prot)
{
    spinlock_lock(&tagstore_lock);
    bool ret = true;
    uint64_t vpn_of_failure = -1;
    uint64_t size_to_revert = 0;
    struct walk_ppns_t walker;
    // init_walker(&walker, vaddr, size);
    // //1st iteration: check if all pages in range belong to enclave
    // while(walk_ppns(&walker, mepc)){
    //     if( ! _destroy_enclave_page_unlocked(walker.current.vpn, walker.current.ppn, walker.current.depth, statuspage_pa, wipe, true)){
    //         ret = false;
    //         goto end;
    //     }
    // }

    if(statuspage_pa){
        assert(statuspage_pa->state == STATE_READY || statuspage_pa->state == STATE_TEARDOWN);
        // statuspage_pa->state = STATE_TEARDOWN;
    }

    //2nd iteration to remove pages
    uint64_t previous_ppn = -1;
    init_walker(&walker, vaddr, size);
    while(walk_ppns(&walker, mepc)){
        if(!_destroy_enclave_page_unlocked(walker.current.vpn, walker.current.ppn, walker.current.depth, statuspage_pa, wipe, false)){
            printtag_error("Failed to destroy enclave pages. Reverting...\n");
            vpn_of_failure = walker.current.vpn;
            size_to_revert = (vpn_of_failure << RISCV_PGSHIFT) - vaddr; //TODO check if off-by-one
            ret = false;
            goto revert;
        }
        if (true == prot)
        {
            ppage(walker.current.vpn*PAGESIZE, false, mepc, vaddr, vaddr+size);
        }
    }

    //3rd iteration: 
    //_After_ we removed the enclave pages, remove HPCE bit if necessary
#if SM_TAG_MEGAPAGES == 1
    uint64_t last_mp_ppn = -1;
    init_walker(&walker, vaddr, size);
    while(walk_ppns(&walker, mepc)){
        //TODO only remove if no other enclave page exists within huge page. 

        // clear mp tag if possible
        uint64_t mp_ppn = walker.current.ppn & ~(0x1ffull);
        if (mp_ppn != last_mp_ppn){
           last_mp_ppn = mp_ppn;
           _clear_megapage_tag_unlocked(mp_ppn, eid); 
        }
    }
#endif
    goto end;
revert:
    printtag_error("Rverting destrying (= re-adding) enclave pages. Note: some pages may have been wiped in the process.\n");
    assert(_va_range_to_enclave(vaddr, size_to_revert, statuspage_pa, mepc, prot, false));
end:
    spinlock_unlock(&tagstore_lock);
    return ret;
}

static bool _va_range_to_enclave(uint64_t vaddr, uint64_t size, e_metapage* statuspage_pa, uint64_t mepc, bool prot, bool zero_mem)
{
    printtag_debug("_va_range_to_enclave(0x%lx, size=%ld, ..., prot=%d, zero_mem=%d)\n", vaddr, size, prot, zero_mem);
    bool ret = true;
    spinlock_lock(&tagstore_lock);
    assert_ifdebug(statuspage_pa);
    assert(statuspage_pa->state == STATE_READY 
        || statuspage_pa->state == STATE_TEARDOWN
        || statuspage_pa->state == STATE_UNINITIALIZED
    );

    uint64_t last_mp_ppn = -1;
    uint64_t vpn_of_failure = -1;
    uint64_t size_to_revert = 0;
    struct walk_ppns_t walker;
    // init_walker(&walker, vaddr, size);
    // while(walk_ppns(&walker, mepc)){
    //     if( ! _make_enclave_page_unlocked(walker.current.vpn, walker.current.ppn, walker.current.depth, walker.current.permissions, statuspage_pa, true, false)){
    //         ret = false;
    //         goto end;
    //     }
    // }

    init_walker(&walker, vaddr, size);
    while(walk_ppns(&walker, mepc)){

#if SM_TAG_MEGAPAGES == 0
        bool tag_megapage = false;
#else
        uint64_t mp_ppn = walker.current.ppn & ~(0x1ffull);
        bool tag_megapage = false;
        if (mp_ppn != last_mp_ppn){
           last_mp_ppn = mp_ppn;
           tag_megapage = true;
        }
#endif

        if( ! _make_enclave_page_unlocked(walker.current.vpn, walker.current.ppn, walker.current.depth, walker.current.permissions, statuspage_pa, false, tag_megapage)){
            printtag_error("Failed to make enclave pages. Reverting...\n");
            vpn_of_failure = walker.current.vpn;
            size_to_revert = (vpn_of_failure << RISCV_PGSHIFT) - vaddr; //TODO check if off-by-one
            ret = false;
            goto revert;
        }
        // clear page content
        if (zero_mem)
        {
            printtag_debug("Wipe page ppn=%lx\n", walker.current.ppn);
            fast_memset((char*)(walker.current.ppn << RISCV_PGSHIFT), 0, PAGESIZE);
        }
        if (true == prot){
            ppage(walker.current.vpn*PAGESIZE, true, mepc, vaddr, vaddr+size);
        }
    }
    goto end;
revert:
    if(!_va_range_remove_from_enclave(vaddr, size_to_revert, statuspage_pa, mepc, false, statuspage_pa->id, prot)){
        printtag_error("Failed to clean up pages.\n");
    }
    ret = false;
end:
    spinlock_unlock(&tagstore_lock);
    printtag_debug("_va_range_to_enclave done.\n");
    return ret;
}
//------------------------------------------------------------------------------

static inline void _swap_mpp(e_metapage* statuspage_pa){
    //TODO do we support S-mode? if yes, TODO all other S-mode registers/CSRs
    //function copied from https://github.com/keystone-enclave/riscv-pk/blob/sm_rs/sm/thread.c
    int curr_mstatus = CSRR(CSR_MSTATUS);
    int old_mpp = statuspage_pa->tcs.mpp;
    if(old_mpp < 0){
        //Old MPP bit isn't initialized!
        old_mpp = curr_mstatus & 0x800;
    }
    statuspage_pa->tcs.mpp = curr_mstatus & 0x800;
    int new_mstatus = (curr_mstatus & ~0x800) | old_mpp;
    CSRW(CSR_MSTATUS, new_mstatus);

}

static inline void _set_interrupt_handling_for_enclave(e_metapage* statuspage_pa){
    #ifdef SM_INTERRUPT_HANDLING

    statuspage_pa->tcs.csrs_host.mideleg = CSRR(CSR_MIDELEG);
    statuspage_pa->tcs.csrs_host.mtvec = CSRR(CSR_MTVEC);
    statuspage_pa->tcs.csrs_host.medeleg = CSRR(CSR_MEDELEG);

    //TODO only if not in_enclave()
    // assert(statuspage_pa->tcs.csrs_host.mideleg == (MIP_SSIP | MIP_STIP | MIP_SEIP));

    //mideleg and medeleg must always be 0. otherwise OS could see/manipulate data.
    assert(statuspage_pa->tcs.csrs_enclave.mideleg == 0);
    assert(statuspage_pa->tcs.csrs_enclave.medeleg == 0);
    //assert((statuspage_pa->tcs.csrs_enclave.medeleg & (1U <<CAUSE_USER_ECALL)) == 0);

    CSRW(CSR_MIDELEG, statuspage_pa->tcs.csrs_enclave.mideleg);
    CSRW(CSR_MEDELEG, statuspage_pa->tcs.csrs_enclave.medeleg);
    CSRW(CSR_MTVEC,   statuspage_pa->tcs.csrs_enclave.mtvec);

    // allow no interrupts here
    //mie_stored = CSRR(CSR_MIE);
    //CSRW(CSR_MIE, 0);

    //*HLS()->timecmp = *mtime + 1000000;
    /*
    if(statuspage_pa->desired_time){
        *HLS()->timecmp = *mtime + statuspage_pa->desired_time;
    }
    */

    #if DEBUG_TAG == 1
    if ((CSRR(CSR_MIP) & MIP_MTIP) && (CSRR(CSR_MIE) & MIP_MTIP)) {
        printtag_error("MIP_MTIP is set. EENTER takes too long... %s:%d\n", __FUNCTION__, __LINE__);
        *HLS()->timecmp = *HLS()->timecmp + 20000000; //300000;
        //*HLS()->timecmp = -1ULL;
        //printtag_error("rdtime  = %lld\n", *mtime);
    }
    #endif

    #endif
}

static inline void _set_interrupt_handling_for_host(e_metapage* statuspage_pa){
    #ifdef SM_INTERRUPT_HANDLING
    CSRW(CSR_MIDELEG, statuspage_pa->tcs.csrs_host.mideleg);
    CSRW(CSR_MTVEC,   statuspage_pa->tcs.csrs_host.mtvec);
    CSRW(CSR_MEDELEG, statuspage_pa->tcs.csrs_host.medeleg);

    //Delegate Interrupts to S-mode
    uintptr_t mip = CSRR(CSR_MIP);
    printMIP(mip);
    if (mip & MIP_MTIP) {
        printtag_debug_interrupt("MIP_MTIP\n");
        //Note: "The MTIP bit is read-only and is cleared by writing to the memory-mapped machine-mode timer compare register"
        CSR_CLEAR(CSR_MIE, MIP_MTIP);
        //CSR_CLEAR(CSR_MIP, MIP_MTIP); // = NOP
        //*HLS()->timecmp = -1ULL;
        CSR_SET(CSR_MIE, MIP_STIP);
        CSR_SET(CSR_MIP, MIP_STIP);
        //printtag_debug_interrupt("CSR_MIP 0x%lx\n", CSRR(CSR_MIP));
        
    }
    if (mip & MIP_MSIP) {
        printtag_debug_interrupt("MIP_MSIP\n");
        CSR_CLEAR(CSR_MIP, MIP_MSIP);
        CSR_SET(CSR_MIP, MIP_SSIP);
    }
    if (mip & MIP_MEIP) {
        printtag_debug_interrupt("MIP_MEIP\n");
        CSR_CLEAR(CSR_MIP, MIP_MEIP);
        CSR_SET(CSR_MIP, MIP_SEIP);
    }

    /*
    extern void redirect_trap(uintptr_t epc, uintptr_t mstatus, uintptr_t badaddr);
    if(mip & MIP_MTIP){
        printtag_debug("before redirect_trap: MIP_MTIP\n");
        *HLS()->timecmp = -1ULL;
        //clear_csr(mip, MIP_MTIP); read-only
        set_csr(mie, MIP_MTIP);

        redirect_trap(CSRR(CSR_MEPC), CSRR(CSR_MSTATUS), CSRR(CSR_MEPC));
    }
    if(mip & MIP_MSIP || mip & MIP_MEIP){
        printtag_debug("before redirect_trap\n");
        //clear M*IP
        redirect_trap(CSRR(CSR_MEPC), CSRR(CSR_MSTATUS), CSRR(CSR_MEPC));
    }
    */
    printtag_debug("_set_interrupt_handling_for_host end\n");


    #endif
}
static void _switch_context_host_to_enclave(e_metapage* statuspage_pa, sm_thread_regs_t* regs, uintptr_t mepc)
{
    uint64_t new_mepc;
    e_metapage* innermost_statuspage_pa = statuspage_pa;

    if(!(statuspage_pa->tcs.mepc_interrupt)){ //EENTER

        if(is_in_enclave())
        {
            printtag_debug_interrupt("enter child enclave \n");

            e_metapage* current_statuspage_pa = (e_metapage*)(CSRR(CSR_U_TCS));
            assert(current_statuspage_pa);
            current_statuspage_pa->current_child_status_page = statuspage_pa;
        }
        else{
            printtag_debug_interrupt("enter enclave form host \n");


        }

        statuspage_pa->tcs.mepc_eenter = mepc;
        printtag_debug("Saved mepc: 0x%lx\n", statuspage_pa->tcs.mepc_eenter);

        printtag_debug("Storing host regs:\n");
        printregs(regs);
        memcpy(&statuspage_pa->tcs.regs_host, regs, sizeof(sm_thread_regs_t));

        new_mepc = statuspage_pa->entry;
        regs->sp = statuspage_pa->tcs.stack + statuspage_pa->tcs.stack_size - 16*sizeof(uint64_t);

    } else { // RESUME

        if(is_in_enclave())
        {
            assert(0 && "this should never happen\n");
        }

        if (statuspage_pa->current_child_status_page)
        {
            printtag_debug_interrupt("resume from interrupt to current child \n");

            innermost_statuspage_pa = statuspage_pa->current_child_status_page;
        }
        else
        {
            printtag_debug_interrupt("resume from interrupt \n");
        }

        new_mepc = statuspage_pa->root_parent_status_page->tcs.mepc_interrupt;
        printtag_debug("Continuing at mepc: 0x%lx\n", new_mepc);

        //restore enclave registers
        memcpy(regs, &innermost_statuspage_pa->tcs.regs_enclave, sizeof(sm_thread_regs_t));
        printtag_debug("Restored enclave regs:\n");
        printregs(regs);
    }

    //backup csrs:
    statuspage_pa->root_parent_status_page->tcs.csrs_host.eam = CSRR(CSR_U_EAM);
    statuspage_pa->root_parent_status_page->tcs.csrs_host.tcs = CSRR(CSR_U_TCS);
    if (is_in_enclave())
    {
        statuspage_pa->tcs.csrs_host.eam = CSRR(CSR_U_EAM);
        statuspage_pa->tcs.csrs_host.tcs = CSRR(CSR_U_TCS);
    }
    //actual enter:
    size_t meid = innermost_statuspage_pa->id;
    CSRW(CSR_U_TCS, innermost_statuspage_pa);
    CSRW(CSR_U_MEID, meid);
    CSRW(CSR_U_EAM, innermost_statuspage_pa->tcs.csrs_enclave.eam);
    CSRW(CSR_MEPC, new_mepc);

    // printtag_always("CSR_U_MEID: %lx; CSR_U_TCS: %lx\n", CSRR(CSR_U_MEID), CSRR(CSR_U_TCS));

    CSR_SET(CSR_U_TAG_CONTROL, TAG_CTRL_NC_PTW_IN_E);
    innermost_statuspage_pa->state = STATE_ENTERED;
    _set_interrupt_handling_for_enclave(innermost_statuspage_pa); // (timer) interrupts should trap to here, so that we can scrub registers before forwarding it to the S-mode

    _swap_mpp(innermost_statuspage_pa);

    flush_microarchitectural_buffers();

}

static void _switch_context_enclave_to_host(e_metapage* statuspage_pa, sm_thread_regs_t* regs, uintptr_t mepc_interrupt)
{
    e_metapage* current_statuspage_pa = (e_metapage*)(CSRR(CSR_U_TCS));
    assert(current_statuspage_pa);


    //backup all registers
    memcpy(&statuspage_pa->tcs.regs_enclave, regs, sizeof(sm_thread_regs_t));
    printtag_debug("Backup enclave regs:\n");
    printregs((sm_thread_regs_t*)regs);

    // printtag_debug("mepc_interrupt: %lx\n", mepc_interrupt);

    if (mepc_interrupt || current_statuspage_pa->parent_id == 0)
    {
        printtag_debug_interrupt("returning to host \n");

        // return to actual host
        
        //restore non-enclave registers
        memcpy(regs, &statuspage_pa->root_parent_status_page->tcs.regs_host, sizeof(sm_thread_regs_t));
        printtag_debug("Restored host regs:\n");
        printregs((sm_thread_regs_t*)regs);
    }
    else
    { 
        printtag_debug_interrupt("returning to parent enclave \n");

        //restore parent enclave registers
        memcpy(regs, &statuspage_pa->tcs.regs_host, sizeof(sm_thread_regs_t));
        printtag_debug("Restored host regs:\n");
        printregs((sm_thread_regs_t*)regs);
    }


    //remember interrupted mepc (and restore at eenter)
    // printtag_debug("mepc_interrupt: %lx\n", mepc_interrupt);
    // printtag_debug("statuspage_pa->root_parent_status_page: %lx\n", statuspage_pa->root_parent_status_page);

    statuspage_pa->root_parent_status_page->tcs.mepc_interrupt = mepc_interrupt;
    printtag_debug_interrupt("Saving interrupt mepc: 0x%lx\n", statuspage_pa->tcs.mepc_interrupt);

    statuspage_pa->root_parent_status_page->state = STATE_READY;

    uint64_t mepc_new = 0;
    
    if(!mepc_interrupt){ //actual exit
        mepc_new = statuspage_pa->tcs.mepc_eenter;
        mepc_new += 4;
        //reset stats in case we want to enter the enclave again
        statuspage_pa->irq_cnt = 0;
        //TODO other fields

        if(current_statuspage_pa->parent_id)
        {
            current_statuspage_pa->parent_status_page->current_child_status_page = 0;
        }
    }
    else 
    {
        mepc_new = statuspage_pa->root_parent_status_page->tcs.mepc_eenter;

    }

    if(!current_statuspage_pa->parent_id || mepc_interrupt)
    {
        // exit to host
        CSRW(CSR_MEPC, mepc_new);
        CSRW(CSR_U_MEID, statuspage_pa->root_parent_status_page->parent_id);
        CSRW(CSR_U_EAM, statuspage_pa->root_parent_status_page->tcs.csrs_host.eam);
        CSRW(CSR_U_TCS, statuspage_pa->root_parent_status_page->tcs.csrs_host.tcs);
        // CSR_CLEAR(CSR_U_TAG_CONTROL, TAG_CTRL_NC_PTW_IN_E);
        // assert(0 && "nesting not implemented");
        CSR_CLEAR(CSR_U_TAG_CONTROL, TAG_CTRL_NC_PTW_IN_E);
        //re-enable interrupt delegation such that the interrupt traps to the OS
        _set_interrupt_handling_for_host(statuspage_pa->root_parent_status_page);
        _swap_mpp(statuspage_pa->root_parent_status_page);
    } else 
    {
        // exit to parent enclave
        CSRW(CSR_MEPC, mepc_new);
        CSRW(CSR_U_MEID, statuspage_pa->parent_id);
        CSRW(CSR_U_EAM, statuspage_pa->tcs.csrs_host.eam);
        CSRW(CSR_U_TCS, statuspage_pa->tcs.csrs_host.tcs);
        // CSR_CLEAR(CSR_U_TAG_CONTROL, TAG_CTRL_NC_PTW_IN_E);
        // assert(0 && "nesting not implemented");
        // CSR_CLEAR(CSR_U_TAG_CONTROL, TAG_CTRL_NC_PTW_IN_E);
        // //re-enable interrupt delegation such that the interrupt traps to the OS
        // _set_interrupt_handling_for_host(statuspage_pa);
        // _swap_mpp(statuspage_pa);
    }
    // printtag_always("CSR_U_MEID: %lx; CSR_U_TCS: %lx\n", CSRR(CSR_U_MEID), CSRR(CSR_U_TCS));

    flush_microarchitectural_buffers();
}

uintptr_t trap_vector_enclave_c(uintptr_t* _regs, uintptr_t future)
//void interrupt_trap(uintptr_t* _regs, uintptr_t mcause, uintptr_t mepc)
{
    uintptr_t cycle_enter = CSRR(CSR_CYCLE);
    assert(is_in_enclave());

    uintptr_t mcause = CSRR(CSR_MCAUSE);
  
    /* ignore IRQ_S_EXT
    if ((mcause & ((1ull<<63)-1)) == IRQ_S_EXT)
    {
        printtag_debug_interrupt("Ignoring IRQ_S_EXT...\n");
        CSR_CLEAR(CSR_MIP, MIP_MEIP);
        return 0;
    }
    */

    uintptr_t mepc = CSRR(CSR_MEPC);
    sm_thread_regs_t* regs = (sm_thread_regs_t*)(_regs + 1);

    printtag_debug_interrupt("trap_vector_enclave_c. mcause = 0x%lx = %s. pc = 0x%lx. mbadaddr = 0x%lx.\n", mcause, _cause_to_str(mcause), mepc, read_csr(mbadaddr));
    printtag_debug_interrupt("trap_vector_enclave_c. time = %d.\n", *mtime);

    e_metapage* statuspage_pa = (e_metapage*)(CSRR(CSR_U_TCS));

    _switch_context_enclave_to_host(statuspage_pa, regs, mepc);

    printtag_debug_interrupt("trap_vector_enclave_c EXIT.. continuing at mepc = 0x%lx\n", CSRR(CSR_MEPC));

    uintptr_t cycle_exit = CSRR(CSR_CYCLE);
    statuspage_pa->irq_cnt++;
    statuspage_pa->irq_delegation_ticks = cycle_exit - cycle_enter;

    return ((sm_thread_regs_t*)regs)->a0;
}

static void _reset_state(e_metapage* statuspage_pa)
{
    statuspage_pa->tcs.mpp                = -1; // <0 or 0x800;
    statuspage_pa->state                  = STATE_READY;
    statuspage_pa->tcs.csrs_enclave.eam   = EAM_ENCLAVE;
}

static inline bool _can_manage_enclave(e_metapage* statuspage_pa)
{
    //assuming statuspage_pa is valid
    size_t current_meid = CSRR(CSR_U_MEID);
    return (
           statuspage_pa->parent_id == current_meid
        || statuspage_pa->id == current_meid
    );
}
static int _is_valid_statuspage(e_metapage* statuspage_pa, union memory_tag * tag)
{
    assert(((uintptr_t)statuspage_pa & 0xFFF) == 0);
    union memory_tag tmp;
    bool tag_valid = read_tag(&tmp, (uintptr_t)statuspage_pa >> RISCV_PGSHIFT);
    if(!tag_valid){
        printtag_error("page not taggable.\n");
        return false;
    }

    if(!tag){
        tag = &tmp;
    }
    if(! tag->bit.immutable){
        printtag_error("Invalid statuspage: ! tag->bit.immutable)\n");
        return 0;
    }
    if(tag->bit.page_type != PT_MONITOR){
        printtag_error("Invalid statuspage: tag->bit.page_type != PT_MONITO)\n");
        return 0;
    }
    //TODO check if monitor page, etc
    if(tag->bit.id == 0 || tag->bit.id == EID_INVALID){
        printtag_error("ID: %d\n", tag->bit.id);
        printtag_error("Invalid statuspage: tag->bit.id == 0 || tag->bit.id == EID_INVALID)\n");
        return 0;
    }
    if(! _eid_exists(tag->bit.id)){
        printtag_error("Invalid statuspage: ! _eid_exists(tag->bit.id))\n");
        return 0;
    }
    if(statuspage_pa->id != tag->bit.id){
        printtag_error("Invalid statuspage: statuspage_pa->id != tag->bit.id)\n");
        return 0;
    }
    return 1;
}

//------------------------------------------------------------------------------
static inline e_metapage* statuspage_va_to_pa(uintptr_t statuspage_va, uint64_t * statuspage_ppn, uintptr_t mepc){
    debug_print_walk = !debug_print_walk;
    uint64_t ppn = getPPN4K(statuspage_va, mepc);
    debug_print_walk = !debug_print_walk;

    e_metapage* statuspage_pa = (e_metapage*)(ppn << RISCV_PGSHIFT);
    if(statuspage_ppn){
        *statuspage_ppn = ppn;
    }
    return statuspage_pa;
}

static void trap_ecreate(sm_thread_regs_t* regs, uintptr_t mepc)
{
    uintptr_t statuspage_va = regs->a1;
    uintptr_t stack         = regs->a2;
    uint64_t  stack_size    = regs->a3;
    uintptr_t code_entry    = regs->a4;
    uint64_t  code_size     = regs->a5;
    ecreate_args_t * ecreate_args_va = (ecreate_args_t *)regs->a6;
    uint64_t desired_time   = 0;
    uint64_t do_ppage = 0;
    if(ecreate_args_va){
        desired_time = load_uint64_t(&(ecreate_args_va->desired_time), mepc);
        do_ppage     = !!load_uint64_t(&(ecreate_args_va->do_ppage), mepc);
        //TODO copy other bytes/words if they exist
    }

    //NOTE i would assume that currently anything that relies on a "writable" but zero-initialized .bss section breaks? (since adding enclave pages makes sure that every virtual page is on a different physical page)
    //TODO check if existing page table permissions match what is expected.

    printtag_debug("[M_CALL] ECREATE - statuspage: %p stack: %p stacksize: %p entry: %p codesize: %p\n", 
        statuspage_va, stack, stack_size, code_entry, code_size);

    assert((statuspage_va & 0xFFF) == 0); // is page aligned
    //before continuing: access all relevant pages to not end up in an inconsistent state:
    access_range_va(statuspage_va, sizeof(e_metapage), mepc);
    access_range_va(stack, stack_size, mepc);
    access_range_va(code_entry, code_size, mepc);

    uint64_t statuspage_ppn;
    e_metapage* statuspage_pa = statuspage_va_to_pa(statuspage_va, &statuspage_ppn, mepc);

    uint64_t e_id = _allocate_eid();
    assert(e_id != (uint64_t)-1);

    // tag statuspage
    union memory_tag meta_tag;
    spinlock_lock(&tagstore_lock);
    bool tag_valid = read_tag(&meta_tag, statuspage_ppn);
    if(!tag_valid){
        printtag_error("page not taggable.\n");
        assert(false);
        return;
    }
    // print_e_metapage(statuspage_pa);
    // printtag_debug("Tag for ppn %x: [", statuspage_ppn); printTag(&meta_tag); printtag_debug2("]\n");

    assert(meta_tag.bit.id == 0 || meta_tag.bit.id == EID_INVALID); //don't accidentally overwrite an existing protected page
    assert(meta_tag.bit.page_type == PT_NORMAL);
    _clear_tag(&meta_tag);
    meta_tag.bit.id = EID_INVALID; //we only set the id when we have finished writing to it. alternatively we could also use the new validated bit in the tag. otherwise there's a race-condition.
    meta_tag.bit.immutable = 1;
    meta_tag.bit.page_type = PT_MONITOR;
    write_tag(&meta_tag, statuspage_ppn);
    _tag_megapage(statuspage_ppn); 

    // set up status page (now that it is protected)
    memset(statuspage_pa, 0, /*RISCV_PGSIZE*/ sizeof(e_metapage));
    //memset(statuspage_pa->tcs, 0, /*RISCV_PGSIZE*/ sizeof(e_tcs_t));
    statuspage_pa->state          = STATE_UNINITIALIZED;
    statuspage_pa->id             = e_id;
    statuspage_pa->tcs.stack      = stack;
    statuspage_pa->tcs.stack_size = stack_size;
    statuspage_pa->entry          = code_entry;
    statuspage_pa->codesize       = code_size;
    statuspage_pa->satp           = CSRR(CSR_SATP);
    statuspage_pa->parent_id      = CSRR(CSR_U_MEID);
    statuspage_pa->mapped_pages   = 0;
    statuspage_pa->desired_time   = desired_time;
    statuspage_pa->irq_cnt        = 0;
    statuspage_pa->ecreate_args_va = ecreate_args_va;
    //TODO memset TCS if separate
    statuspage_pa->tcs.csrs_enclave.eam      = EAM_ENCLAVE;
    statuspage_pa->tcs.csrs_enclave.tcs      = (uint64_t)statuspage_pa;
    statuspage_pa->tcs.csrs_enclave.mtvec    = (uint64_t)&trap_vector_enclave;
    statuspage_pa->tcs.csrs_enclave.mideleg  = 0;
    statuspage_pa->tcs.csrs_enclave.medeleg  = 0;//CSRR(CSR_MEDELEG) & ~(1U << CAUSE_USER_ECALL);
    statuspage_pa->current_child_status_page = 0;
    statuspage_pa->root_parent_status_page   = 0;
    statuspage_pa->parent_status_page        = 0;
    statuspage_pa->child_ctr                 = 0;

    //TODO ECREATE flag that makes all PTEs immutable for a given enclave


    // tag statuspage again after setting state to UNINITIALIZED
    meta_tag.bit.id = e_id; //TODO monitor id or proper pagetype
    printtag_debug("tagging statuspage with id: %d\n", e_id);
    // printtag_debug("statuspage_pa->parent_id: %d\n", statuspage_pa->parent_id);
    write_tag(&meta_tag, statuspage_ppn);
    spinlock_unlock(&tagstore_lock);

    // tag stack
    assert(_va_range_to_enclave(stack, stack_size, statuspage_pa, mepc, do_ppage, false));
    // tag code
    assert(_va_range_to_enclave(code_entry, code_size, statuspage_pa, mepc, do_ppage, false));

    //count initial (code+stack) pages
    statuspage_pa->mapped_pages_init = statuspage_pa->mapped_pages;

    //TODO optional: ppage for stack + code

    // Set root parent id for interrupt handling in nested child enclaves
    if(statuspage_pa->parent_id == 0 )
    {
        statuspage_pa->root_parent_status_page = statuspage_pa;
    }
    else
    {
        e_metapage* current_statuspage_pa = (e_metapage*)(CSRR(CSR_U_TCS));
        assert(current_statuspage_pa);
        statuspage_pa->root_parent_status_page = current_statuspage_pa->root_parent_status_page;
        statuspage_pa->parent_status_page = current_statuspage_pa;
        current_statuspage_pa->child_ctr++;
        // printtag_always("trap_ecreate statuspage_pa->parent_status_page 0: %p %d\n", statuspage_pa->parent_status_page, current_statuspage_pa->child_ctr);
    }
    // printtag_always("trap_ecreate statuspage_pa->parent_status_page 1: %p\n", statuspage_pa->parent_status_page);

    _reset_state(statuspage_pa);
    // printtag_always("trap_ecreate statuspage_pa->parent_status_page 2: %p\n", statuspage_pa->parent_status_page);

    assert(_is_valid_statuspage(statuspage_pa, NULL));

    // printtag_always("ecreate\n");

#if DEBUG_TAG == 1 && 0
    print_e_metapage(statuspage_pa);
    trap_debug(NULL, 0);
#endif
}
//------------------------------------------------------------------------------

static void trap_eenter(sm_thread_regs_t* regs, uintptr_t mepc)
{
    uintptr_t start_ticks = CSRR(CSR_CYCLE);

    printtag_debug("rdtime  = %lld\n", *mtime);
    printtag_debug("[M-CALL] EENTER statuspage_va = %lx\n", regs->a1);
    uintptr_t statuspage_va = regs->a1;
    uint64_t statuspage_ppn;
    e_metapage* statuspage_pa = statuspage_va_to_pa(statuspage_va, &statuspage_ppn, mepc);

    // print_e_metapage(statuspage_pa);
    //check status page
    assert(_is_valid_statuspage(statuspage_pa, NULL));
    assert(statuspage_pa->state == STATE_READY);
    assert(statuspage_pa->satp == CSRR(CSR_SATP));
    assert(statuspage_pa->parent_id == CSRR(CSR_U_MEID));

    _switch_context_host_to_enclave(statuspage_pa, regs, mepc);

    printtag_debug("EENTER DONE\n");
    printtag_debug("rdtime  = %lld\n", *mtime);
    uintptr_t end_ticks = CSRR(CSR_CYCLE);
    statuspage_pa->irq_return_ticks = end_ticks - start_ticks;

#ifdef SM_INTERRUPT_HANDLING
    if ((CSRR(CSR_MIP) & MIP_MTIP) && (CSRR(CSR_MIE) & MIP_MTIP)) {
        printtag_debug("MIP_MTIP shouldnt be set here => misconfigured timer interrupt? %s:%d\n", __FUNCTION__, __LINE__);
        printtag_debug("rdtime  = %lld\n", *mtime);
        printtag_debug("timecmp = %lld\n", *HLS()->timecmp);
    }
#endif
}
//------------------------------------------------------------------------------

static void trap_edestroy(sm_thread_regs_t* regs, uintptr_t mepc)
{
    printtag_debug("[M-CALL] EDESTROY\n");
    uintptr_t statuspage_va = regs->a1;
    e_metapage* statuspage_pa = statuspage_va_to_pa(statuspage_va, NULL, mepc);
    
    // printtag_always("edestroy\n");
    // print_e_metapage(statuspage_pa);
    // if(statuspage_pa->parent_id){
    // printtag_always("edestroy parent page\n");
    //     print_e_metapage(statuspage_pa->parent_status_page);
    // }
    // printtag_error("Interrupts during enclave execution: %ld\n", statuspage_pa->irq_cnt);
    // printtag_error("Interrupt delegation ticks: %ld\n", statuspage_pa->irq_delegation_ticks);
    // printtag_error("Interrupt return to enclave ticks: %ld\n", statuspage_pa->irq_return_ticks);
    assert(_is_valid_statuspage(statuspage_pa, NULL));
    // printtag_always("trap_edestroy statuspage_pa->parent_id: %d\n", statuspage_pa->parent_id);
    // printtag_always("trap_edestroy statuspage_pa->id: %d\n", statuspage_pa->id);
    // printtag_always("trap_edestroy statuspage_pa->child_ctr: %d\n", statuspage_pa->child_ctr);
    // printtag_always("trap_edestroy statuspage_pa->parent_status_page 1: %p\n", statuspage_pa->parent_status_page);
    // if(statuspage_pa->parent_status_page){
        // printtag_always("trap_edestroy statuspage_pa->parent_status_page->child_ctr 1: %d\n", statuspage_pa->parent_status_page->child_ctr);
    // }
    
    
    assert(statuspage_pa->child_ctr == 0 && "enclave has active childs\n");
    //check if we are allowed to manipulate/manage this enclave
    assert(_can_manage_enclave(statuspage_pa));

    //make sure target enclave is in proper state:
    //TODO: check if any threads running
    assert(statuspage_pa->state == STATE_READY || statuspage_pa->state == STATE_TEARDOWN);
    statuspage_pa->state = STATE_TEARDOWN;

    //wipe and unassign all pages
    assert(statuspage_pa->mapped_pages == statuspage_pa->mapped_pages_init);
    assert(_va_range_remove_from_enclave(statuspage_pa->tcs.stack, statuspage_pa->tcs.stack_size, statuspage_pa, mepc, true, statuspage_pa->id, true));
    assert(_va_range_remove_from_enclave(statuspage_pa->entry, statuspage_pa->codesize, statuspage_pa, mepc, false, statuspage_pa->id, true));
    //TODO: if statuspage_pa->mapped_pages == statuspage_pa->mapped_pages_init => check all tags for entire ram?

    if(statuspage_pa->parent_id)
    {
        statuspage_pa->parent_status_page->child_ctr--;
        // printtag_always("trap_edestroy statuspage_pa->parent_status_page 2: %p %d\n", statuspage_pa->parent_status_page, statuspage_pa->parent_status_page->child_ctr);
    }

    //wipe and unassign statuspage(s)
    uint64_t eid = statuspage_pa->id;
    _deallocate_eid(statuspage_pa->id);
    assert(_va_range_remove_from_enclave(statuspage_va, RISCV_PGSIZE, NULL, mepc, true, eid, true));

    printtag_debug("edestroy done\n");
}
//------------------------------------------------------------------------------

static void trap_eadd(sm_thread_regs_t* regs, uintptr_t mepc)
{
    printtag_debug("[M-CALL] EADD\n");
    uintptr_t statuspage_va = regs->a1;
    uintptr_t vaddr         = regs->a2;
    uintptr_t size          = regs->a3;
    uintptr_t prot          = regs->a4;
    uintptr_t zero_mem      = regs->a5;

    e_metapage* statuspage_pa = statuspage_va_to_pa(statuspage_va, NULL, mepc);
    assert(_is_valid_statuspage(statuspage_pa, NULL));

    assert(statuspage_pa->state == STATE_READY || statuspage_pa->state == STATE_ENTERED);
    assert(_can_manage_enclave(statuspage_pa));

    assert(_va_range_to_enclave(vaddr, size, statuspage_pa, mepc, !!prot, !!zero_mem));
}
//------------------------------------------------------------------------------

static void trap_eremove(sm_thread_regs_t* regs, uintptr_t mepc)
{
    printtag_debug("[M-CALL] EREMOVE\n");
    uintptr_t statuspage_va = regs->a1;
    uintptr_t vaddr         = regs->a2;
    uintptr_t size          = regs->a3;
    uintptr_t prot          = regs->a4;

    assert(IS_PAGE_ALIGNED(vaddr));
    e_metapage* statuspage_pa = statuspage_va_to_pa(statuspage_va, NULL, mepc);
    assert(_is_valid_statuspage(statuspage_pa, NULL));

    assert(statuspage_pa->state == STATE_READY || statuspage_pa->state == STATE_TEARDOWN);
    assert(_can_manage_enclave(statuspage_pa));
    // statuspage_pa->state = STATE_TEARDOWN;
    //TODO should be let the user allow to remove initial code+stack pages? because they are removed at edestroy
    assert(_va_range_remove_from_enclave(vaddr, size, statuspage_pa, mepc, true, statuspage_pa->id, !!prot));
}
//------------------------------------------------------------------------------

extern uintptr_t max_ppn, min_ppn;
static void trap_debug(sm_thread_regs_t* regs, uintptr_t mepc)
{
    printtag_always("[M-CALL] DEBUG\n");
    printtag_always("min_ppn = %x\n", min_ppn);
    printtag_always("max_ppn = %x\n", max_ppn);
    union memory_tag tag = {0};
    for (uintptr_t ppn = min_ppn; ppn < max_ppn; ppn++)
    {
        read_tag(&tag, ppn);
        if(tag.direct64[0] || tag.direct64[1])
        {
            printtag_always("Tag for ppn %x: [", ppn); printTagGeneric(&tag, printtag_always2); printtag_always2("]\n");
        }
    }
}

//------------------------------------------------------------------------------

static void trap_set_fence(sm_thread_regs_t* regs, uintptr_t mepc)
{
    printtag_always("[M-CALL] set fence\n");
    uint64_t arg = regs->a1;
    use_fence_t = !!arg;
}

//------------------------------------------------------------------------------

static void trap_eexit(sm_thread_regs_t* regs, uintptr_t mepc)
{
    assert(is_in_enclave());

    printtag_debug("[M-CALL] EEXIT\n");
    uint64_t a0 = regs->a1; //Note: return value (a0) is moved to a1 before EEXIT is called
    uint64_t a1 = regs->a2; //Note: return value (a1) is moved to a2 before EEXIT is called
    printtag_debug("EEXIT return value = 0x%lx\n", a0);

    e_metapage* statuspage_pa = (e_metapage*)(CSRR(CSR_U_TCS));
    assert(statuspage_pa);


    _switch_context_enclave_to_host(statuspage_pa, regs, 0);
    _reset_state(statuspage_pa);

    if(statuspage_pa->ecreate_args_va){
        store_uint64_t(&(statuspage_pa->ecreate_args_va->out_irq_cnt), statuspage_pa->irq_cnt, mepc);
        store_uint64_t(&(statuspage_pa->ecreate_args_va->out_irq_delegation_ticks), statuspage_pa->irq_delegation_ticks, mepc);
        store_uint64_t(&(statuspage_pa->ecreate_args_va->out_irq_return_ticks), statuspage_pa->irq_return_ticks, mepc);
    }

    regs->a0 = a0;
    //regs->a1 = a1; //TODO a1 may also contain a return value. see tag_api.h. //TODO how to deal with functions that use both registers? unsupported for now. future: need 2 different eenter macros or set return value to statuspage somewhere!

    printtag_debug("EEXIT done\n");
    printtag_debug("rdtime  = %lld\n", *mtime);
}

//------------------------------------------------------------------------------

static inline bool _PTE_points_to_protected_page(PTE_64_Union pte)
{
    assert_ifdebug(pte.raw_value & PTE_V);
    union memory_tag tag;
    bool has_tag = read_tag(&tag, pte.pte.ppn);
    if(!has_tag){
        return false;
    }
    uint64_t page_is_secure = tag.bit.immutable || (tag.bit.id != 0) || tag.bit.page_type == PT_ENCLAVE;
    if(page_is_secure){
        return true;
    }
    return false;
}

static void trap_ppage(sm_thread_regs_t* regs, uintptr_t mepc)
{
    uintptr_t vaddr = regs->a1;
    int64_t prot    = regs->a2;
    ppage(vaddr, prot, mepc, vaddr, vaddr+PAGESIZE);
}
static void ppage(uintptr_t vaddr, int64_t prot, uintptr_t mepc, uintptr_t vaddr_range_start, uintptr_t vaddr_range_end)
{
    //TODO add statuspage_pa to interface (for debugging)

    printtag_debug("PPAGE: %s 0x%lx\n", prot ? "Protect" : "Release", vaddr);
    uint64_t satp = CSRR(CSR_SATP);
    #if DEBUG_TAG == 1
        printSATP(satp);
    #endif


    if(prot == 0){
        //assert(is_in_enclave());
    }

    //walk once such that mapping is valid (because it triggers page faults)
    //also, walk, such that we can then traverse in the other direction.
    //Sv48 can have 4 levels
    #define MAX_LEVELS 5
    PTE_64_Union ptes[MAX_LEVELS] = {0,};
    PTE_64_Union * ptrs_to_ptes[MAX_LEVELS] = {0,};
    PTE_64_Union tmp = {.raw_value = 0};
    PTE_64_Union * tmp2 = NULL;
    int16_t depth = -1;
    debug_print_walk = !debug_print_walk;
    while (walk_next(vaddr, mepc, &depth, &tmp, &tmp2)) {
        ptes[depth] = tmp;
        ptrs_to_ptes[depth] = tmp2;
        // printtag_debug("@ %lx:ptes[%d] = ", ptrs_to_ptes[depth], depth);
        // printPTE(ptes[depth].raw_value, 1, depth);
    }
    debug_print_walk = !debug_print_walk;
    assert(depth == 0);
    assert(!PTE_TABLE(ptes[0].raw_value));
    assert(ptes[0].raw_value & PTE_V);
    //treat satp as a pte and add it to list
    uint64_t max_depth = SATPtoDepth(satp);
    assert_ifdebug(max_depth >= 0 && max_depth < MAX_LEVELS);
    assert_ifdebug(ptes[max_depth-1].raw_value != 0);
    assert_ifdebug(ptes[max_depth].raw_value != 0);
    assert_ifdebug(ptes[max_depth+1].raw_value == 0);
    PTE_64_Union pte = ptes[max_depth+1];
    ptes[max_depth+1].raw_value = 0;
    ptes[max_depth+1].pte.ppn = SATPtoPPN(satp);
    ptes[max_depth+1].pte.valid = 1;


#if DEBUG_TAG == 1 && 1
    // for the given VA, print the PTEs from all layers
    printtag_debug("--------\n");
    for (size_t depth = 0; depth < MAX_LEVELS; depth++){
        if(ptes[depth].raw_value){
            // printtag_debug("@ %lx : ptes[%d] = ", ptrs_to_ptes[depth], depth);
            printtag_debug("ptes[%d] = ", depth);
            printPTE(ptes[depth].raw_value, 1, depth);
        }
    }
    printtag_debug("--------\n");
#endif

    //TODO assert that page is actually an enclave page

    //traverse, starting from the leaf-page
    // printtag_debug("PPAGE: traverse, starting from the leaf-page\n");
    for (size_t depth = 0; depth < MAX_LEVELS; depth++)
    {
        uint64_t has_protected = 0;
        PTE_64_Union pte = ptes[depth];
        if(!pte.raw_value){
            break; //reached root
        }
        // printtag_debug("PPAGE depth = %ld\n", depth);
        
        union memory_tag tag;
        bool tag_valid = read_tag(&tag, pte.pte.ppn);
        if(!tag_valid){
            printtag_error("page not taggable.\n");
            return;
            //TODO error recovery and undo stuff
        }

        printtag_debug(""); printPTE(pte.raw_value, 1, depth);

        if(!PTE_TABLE(pte.raw_value)){
            //leaf
            assert_ifdebug(depth == PL_KILO);
            assert_ifdebug(tag.bit.page_level == depth);
            //assert(tag.bit.id != 0);
            //assert(tag.bit.page_type == PT_ENCLAVE);
        }else{ // page table
            size_t depth_next = depth - 1;
            size_t index_to_ignore = vaddr ? getVPNpart((uintptr_t)vaddr, depth_next)  : -1;
            if(prot){
                assert(tag.bit.id == 0 && (tag.bit.page_type == 0 || tag.bit.page_type == PT_PAGETABLE));
                //assert(tag.bit.immutable == 0);

                // printtag_debug("checkig if we can set entire PT to validated (if all entries point to E pages).\n");
                // if(index_to_ignore == 0){
                //     printtag_warning("index_to_ignore = %3d ", index_to_ignore);
                //     printtag_warning("vaddr  = 0x%lx ", vaddr);
                //     printtag_warning("vaddr+ = 0x%lx ", vaddr+0x1FF000);
                //     // printtag_warning("vaddr_range_start = 0x%lx ", vaddr_range_start);
                //     printtag_warning("vaddr_range_end = 0x%lx ", vaddr_range_end);
                //     // printtag_warning("aligned = %1d ", !(vaddr_range_start & 0x1FFFFF));
                //     printtag_warning("inrange = %1d ", (vaddr + 0x1FF000) < vaddr_range_end); 
                //     printtag_warning("\n");
                // }
                if(!tag.bit.validated
                    // && prot
                    && index_to_ignore == 0
                    && (vaddr + 0x1FF000) < vaddr_range_end
                // ROUND_UP_2MPAGE
                // ROUND_DOWN_2MPAGE
                // if(!tag.bit.validated && index_to_ignore == 511 && prot && ((vaddr_range_start & 0x1FFFFF) == 0)
                ){
                    // printtag_warning("setting validated bit for pagetable\n");
                    // printtag_warning("setting validated bit for pagetable\n");
                    tag.bit.validated = 1;
                    write_tag(&tag, pte.pte.ppn);
                    printtag_debug("after write_tag "); printPTE(pte.raw_value, 1, depth);
                }


                if(tag.bit.immutable && tag.bit.page_type == PT_PAGETABLE){
                    //already protected. nothing to do.
                    // printtag_debug(""); printPTE(ptes[depth].raw_value, 0, depth);
                    printtag_debug("already protected. nothing to do.\n");
                    // continue; //or break and assume parent PTEs are also correct.
                    break;
                }

            }
            printtag_debug("PPAGE depth = %ld. visiting all PTEs for PT 0x%lx: \n", depth, pte.pte.ppn);
            assert_ifdebug(depth);
            uint64_t current_vaddr = 0; //TODO
            printtag_debug("PT  "); printPTE(pte.raw_value, 1, depth_next);
            PTE_64_Union* page_table = (PTE_64_Union*)(pte.pte.ppn * (uint64_t)RISCV_PGSIZE);
            size_t i_start = (vaddr == vaddr_range_start) ? 0 : index_to_ignore + 1;
            //note: we set i_start to the next index because we already searched through all previous indices before
            //to skip this optimization: set i_start to 0 (and re-add the i == index_to_ignore check)
            // has_protected
            for (size_t i = i_start; i < 512; i++) {
                // if(i == index_to_ignore){
                    // continue;
                // }
                PTE_64_Union pte_inner = page_table[i];
                if(pte_inner.pte.valid){
                    #if 0
                        printtag_debug(" -- "); printPTE(pte_inner.raw_value, 1, depth_next);
                    #endif
                    bool _is_protected = _PTE_points_to_protected_page(pte_inner);
                    if(_is_protected){
                        has_protected = _is_protected;
                        break;
                    }
                }
            }
            printtag_debug("has protected pages: %3ld\n", has_protected);

            if(prot && has_protected){
                printtag_debug("Note has_protected should be zero but it isnt because we dont necessarily automatically protect pagetables when creating enclaves and their (meta)pages.\n");
                // TODO assert(!has_protected);
            }

            //printPTE(pte.raw_value, 1, depth);
            //dont unprotect current level if any PTEs in current PT have protected pages.
            has_protected      = prot ? 1 : has_protected;
            tag.bit.immutable  = has_protected;
            tag.bit.page_type  = has_protected ? PT_PAGETABLE : 0;
            tag.bit.page_level = has_protected ? depth : 0;
            tag.bit.validated  = tag.bit.validated && prot ? 1 : 0;
            write_tag(&tag, pte.pte.ppn);
            printtag_debug("after write_tag "); printPTE(pte.raw_value, 1, depth);
        }
        //TODO check if not already immutable, page-type, etc
        //TODO checks? (e.g., dont allow unprotecting from outside enclave (unless as part of edestroy?))


        if (prot){
            _tag_megapage(pte.pte.ppn);
        }
    }

    //make sure that no aliases exist for this page.
    printtag_debug("Traversing entire page table to make sure no aliases exist in this process\n");
    if (prot){
        //only when adding a page
        assert(!ppn_is_mapped(SATPtoPPN(satp), SATPtoDepth(satp)+1, 0, ptes[0].pte.ppn, vaddr));
    }

    printtag_debug("PPAGE done.\n");
}

bool ppn_is_mapped(uint64_t ppn_of_page_table, size_t depth, uint64_t current_vaddr, uint64_t ppn, uint64_t vaddr_to_ignore){
    PTE_64_Union* page_table = (PTE_64_Union*)(ppn_of_page_table * (uint64_t)RISCV_PGSIZE);
    printtag_debug("ppn_is_mapped(0x%lx,%d,0x%lx,0x%lx,0x%lx)\n", ppn_of_page_table, depth, current_vaddr, ppn, vaddr_to_ignore);
    union memory_tag tag_of_page_table;
    bool tag_valid = read_tag(&tag_of_page_table, ppn_of_page_table);
    if(!tag_valid){
        printtag_error("page not taggable.\n");
        return false;
    }
    if(!tag_of_page_table.bit.immutable){
        printtag_debug("pagetable @ 0x%lx is not immutable. skipping.\n", ppn_of_page_table);
        return false;
    }
    assert_ifdebug(tag_of_page_table.bit.page_type == PT_PAGETABLE);
    if(tag_of_page_table.bit.validated){
        printtag_debug("pagetable @ 0x%lx only contains validated/enclave mappings. skipping.\n", ppn_of_page_table);
        // printtag_warning("pagetable @ 0x%lx only contains validated/enclave mappings. skipping.\n", ppn_of_page_table);
        return false;
    }


    assert_ifdebug(depth);
    assert_ifdebug(vaddr_to_ignore == (vaddr_to_ignore >> RISCV_PGSHIFT) << RISCV_PGSHIFT);
    size_t next_depth = depth - 1;
    // size_t enclave_entries = 0; //TODO only works for 4k pages currently
    for (size_t i = 0; i < 512; i++){
        PTE_64_Union pte = page_table[i];
        if (!pte.pte.valid){
            continue;
        }
        uint64_t mask = (0x1FFULL << (12 + 9 * next_depth));
        current_vaddr = current_vaddr & ~mask;
        current_vaddr |= i << (12 + 9 * next_depth);
        // printtag_debug("i %d next_depth %d\n", i, next_depth);
        // printtag_debug("mask          = 0x%lx\n", mask);
        // printtag_debug("current_vaddr = 0x%lx\n", current_vaddr);

        if(PTE_TABLE(pte.raw_value)){
            if(ppn_is_mapped(pte.pte.ppn, next_depth, current_vaddr, ppn, vaddr_to_ignore)){
                return true;
            }
        }else{ // leaf page
            #if DEBUG_TAG == 1 && 0
                union memory_tag tag_of_pte_target = {0};
                printtag_debug(COLOR_GRAY "0x%lx[0x%x]->0x%lx VPN 0x%lx ", ppn, i, pte.pte.ppn, current_vaddr>>12);
                bool tag_valid = read_tag(&tag_of_pte_target, pte.pte.ppn);
                printtag_debug2("Tag: "); printTag(&tag_of_pte_target); printtag_debug2("\n");
            #endif
            // if(!tag_of_page_table.bit.validated){
            //     bool tag_valid = read_tag(&tag_of_pte_target, pte.pte.ppn);
            //     bool page_is_secure = /*tag_of_pte_target.bit.immutable || (tag_of_pte_target.bit.id != 0) ||*/ tag_of_pte_target.bit.page_type == PT_ENCLAVE;
            //     enclave_entries += !!page_is_secure;
            // }
            if(pte.pte.ppn == ppn && current_vaddr != vaddr_to_ignore){
                printtag_error("Found (alias) mapping at vaddr = 0x%lx.\n", current_vaddr);
                return true;
            }
        }
    }
    // if(enclave_entries == 512){
    //     assert(0);
    // }
    return false;
}

static void trap_ltag2(sm_thread_regs_t* regs, uintptr_t mepc)
{
    uintptr_t vaddr = regs->a1;
    printtag_debug("LTAG2: addr: 0x%lx\n", vaddr);
    uintptr_t ppn = getPPN4K(vaddr, mepc);
    union memory_tag tag = {0,};
    read_tag(&tag, ppn);
    regs->a0 = tag.direct64[0];
    regs->a1 = tag.direct64[1];
}

static uintptr_t trap_ltag(sm_thread_regs_t* regs, uintptr_t mepc)
{
    uintptr_t vaddr = regs->a1;
    int offset      = regs->a2;
    printtag_debug("LTAG: addr: 0x%lx offset: %d\n", vaddr, offset);

    assert(offset >= 0 && offset < 2);  //TODO graceful error handling everywhere

    uintptr_t ppn = getPPN4K(vaddr, mepc);
    union memory_tag tag = {0};
    read_tag(&tag, ppn);

    return tag.direct64[offset];
}

static void trap_stag(sm_thread_regs_t* regs, uintptr_t mepc)
{
    uintptr_t vaddr = regs->a1;
    uintptr_t tagl  = regs->a2;
    uintptr_t tagh  = regs->a3;
    printtag_debug("STAG: addr: 0x%lx value: 0x%lx 0x%lx\n", vaddr, tagh, tagl);

    VA va = {.raw = vaddr};
    uintptr_t ppn = getPPN4K(vaddr, mepc);
    //NOTE: if large pages: for non-enclave operations we don't need to tag all 4k pages, because that is likely not what the user wants to do here.

    union memory_tag tag_new = { .direct64 = {tagl, tagh} };
    union memory_tag tag_previous = {0};

    bool tag_valid = read_tag(&tag_previous, ppn);
    if(!tag_valid){
        printtag_error("page not taggable.\n");
        return;
    }
    if(tag_previous.bit.id){
        assert(is_in_enclave());
        assert(CSRR(CSR_U_MEID) == tag_previous.bit.id);
        return;
    }

    union memory_tag allowed = {0}; //the user can only set tag bits that are set to 1 here
    allowed.bit.mpk    = -1;
    allowed.bit.unused = -1;

    printtag_debug("tag_previous: "); printTag(&tag_previous); printtag_debug2("\n");
    printtag_debug("tag_new: "); printTag(&tag_new); printtag_debug2("\n");
    printtag_debug("allowed: "); printTag(&allowed); printtag_debug2("\n");

    tag_new.direct64[0] = (tag_new.direct64[0] & allowed.direct64[0]) | (tag_previous.direct64[0] & ~allowed.direct64[0]);
    tag_new.direct64[1] = (tag_new.direct64[1] & allowed.direct64[1]) | (tag_previous.direct64[1] & ~allowed.direct64[1]);

    printtag_debug("tag_new: "); printTag(&tag_new); printtag_debug2("\n");

    write_tag(&tag_new, ppn);

    printtag_debug("Store tag for PPN 0x%lx: ", ppn); printTag(&tag_new); printtag_debug2("\n");
}

static void trap_tagreset(sm_thread_regs_t* regs, uintptr_t mepc)
{
    uint64_t mode = regs->a1;
    uint64_t tag_ctrl_flags = regs->a2;
    printtag_debug("TAGRESET: mode = %d (%s)\n", mode, tagmode_to_str(mode));

    if( (mode != MTAG0) && (mode != MTAG32) && (mode != MTAG64) && (mode != MTAG128) ){
        uint64_t mode = CSRR(CSR_U_TAG_MODE);
        printtag_debug("returning current mode (=%ld = %s) instead of resetting it.\n", mode, tagmode_to_str(mode));
        regs->a0 = mode;
        return;
    }

    tag_init(0, 0, mode, tag_ctrl_flags);
    regs->a0 = CSRR(CSR_U_TAG_MODE);
}
