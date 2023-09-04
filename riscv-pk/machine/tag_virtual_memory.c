#include "tag.h"
#include "tag_debug.h"
#include <string.h>

extern bool debug_print_walk;

inline void access_range_va(uint64_t vaddr, uint64_t size, uint64_t mepc){
    //TODO if possible: trigger page-fault such that we can continue in m-mode such that our functions dont need to be reentered.
    for (char* p = (char*)vaddr; p < (char*)vaddr+ROUND_UP_PAGE(size); p=(char*)p+PAGESIZE) {
        volatile uint8_t _tmp = load_uint8_t((const uint8_t*)p, mepc);
    }
}
/*
inline void visit_all_PTEs_in_PT(PTE_64_Union current_pte, int16_t depth, uint64_t vaddr_to_ignore, void* custom, bool (*func)(PTE_64_Union*, size_t, PTE_64_Union, int16_t, void*)){
    assert(PTE_TABLE(current_pte.raw_value));
    assert(func);
    PTE_64_Union* page_table = (PTE_64_Union*)(current_pte.pte.ppn * (uint64_t)RISCV_PGSIZE);
    size_t index_to_ignore = vaddr_to_ignore ? getVPNpart((uintptr_t)vaddr_to_ignore, depth)  : -1;

    printtag_debug("PT  "); printPTE(current_pte.raw_value, 1, depth);

    for (size_t i = 0; i < 512; i++) {
        if(i == index_to_ignore){
            continue;
        }
        PTE_64_Union pte = page_table[i];
        if(pte.pte.valid){
            if(func(page_table, i, pte, depth - 1, custom)){
                break;
            }
        }
    }
}
*/
/*
inline uint64_t getVPNpartMask(uint8_t vpn_index){
    assert_ifdebug(vpn_index < 4);
    uint64_t result = ((uintptr_t)PML1_MASK << (9*vpn_index));
    return result;
}
*/

inline uint16_t getVPNpart(uintptr_t vaddr, uint8_t vpn_index){
    assert_ifdebug(vpn_index < 4);

    uint16_t result = (vaddr & ((uintptr_t)PML1_MASK << (9*vpn_index))) >> (RISCV_PGSHIFT + (9*vpn_index));

    #if DEBUG_TAG == 1 && 0
        for (int i = 3; i >= 0; i--) {
            printtag_debug("VPN[%d] = 0x%x\n", i, (vaddr & ((uintptr_t)PML1_MASK << (9*i))) >> (RISCV_PGSHIFT + (9*i)));
        }
        printtag_debug("pg_off = 0x%x\n", vaddr & 0xFFF);
        //printtag_debug("\n");
        printtag_debug("getVPNpart(0x%lx, %d) = 0x%lx\n", vaddr, vpn_index, result);

        //different way of calculating offset
        VA va = {.raw = vaddr};
        switch (vpn_index) {
            case 0:  assert(result == va.fields.vpn0); break;
            case 1:  assert(result == va.fields.vpn1); break;
            case 2:  assert(result == va.fields.vpn2); break;
            case 3:  assert(result == va.fields.vpn3); break;
            default: assert(0); break;
        }

        //different way of calculating offset
        uint16_t pt_idx[4];
        pt_idx[3] = (vaddr & PML4_MASK) >> 39;
        pt_idx[2] = (vaddr & PML3_MASK) >> 30;
        pt_idx[1] = (vaddr & PML2_MASK) >> 21;
        pt_idx[0] = (vaddr & PML1_MASK) >> 12;
        uint16_t idx = pt_idx[vpn_index];
        assert(idx == result);

    #endif

    return result;
}
int walk_next(uintptr_t vaddr, uintptr_t mepc, int16_t * depth, PTE_64_Union * current_pte, PTE_64_Union ** ptr_to_current_pte){
    assert_ifdebug(depth);
    assert_ifdebug(current_pte);

    if(current_pte->raw_value && *depth < 0){
        printtag_warning("already done\n");
        assert(0);
        return 0;
    }

    uint64_t ppn_of_page_table = 0;

    if(!current_pte->raw_value || *depth < 0){
        uint64_t satp = CSRR(CSR_SATP);
        #if DEBUG_TAG == 1
            if(debug_print_walk){
                // printSATP(satp);
            }
        #endif

        *depth = SATPtoDepth(satp);

        ppn_of_page_table = satp & SATP64_PPN;
        goto return_pte;
    }

    if(!PTE_TABLE(current_pte->raw_value)) {
        //current is already a leaf
        return 0;
    } else {
        assert_ifdebug(*depth > 0);
        *depth = *depth - 1;
        ppn_of_page_table = current_pte->pte.ppn;
        goto return_pte;
    }

    PTE_64_Union* page_table = NULL;
    PTE_64_Union pte;
    PTE_64_Union * ptr_to_pte;
return_pte:
    page_table = (PTE_64_Union*)(ppn_of_page_table * RISCV_PGSIZE);
    //printtag_debug("\n", vaddr);
    ptr_to_pte = &(page_table[getVPNpart(vaddr, *depth)]);
    pte = *ptr_to_pte;
    //printtag_debug(""); printPTE(pte.raw_value, 0, *depth);
    if (!pte.pte.valid)
    {
        printtag_debug("Encountered invalid page (VA=0x%lx). Triggering Page-Fault...\n", vaddr);
        access_range_va(vaddr, PAGESIZE, mepc);
        assert(0);
    }

    *current_pte = pte;
    *ptr_to_current_pte = ptr_to_pte;
    #if DEBUG_TAG == 1
        if(debug_print_walk){
            printtag_debug("");
            printPTE(pte.raw_value, 1, *depth);
        }
    #endif
    return 1;

}

inline PTE_64_Union walk(uintptr_t vaddr, uintptr_t mepc, int16_t * depth, void* custom, void (*func)(PTE_64_Union, int16_t, void*))
{
#if DEBUG_TAG == 1
    if(debug_print_walk){
        printtag_debug("Walking... VADDR = %p\n", vaddr);
    }
#endif
    PTE_64_Union * ptr_to_pte = NULL;
    PTE_64_Union pte = {.raw_value = 0};
    assert_ifdebug(func == NULL && custom == NULL);
    // if(func){
        // while (walk_next(vaddr, mepc, depth, &pte, &ptr_to_pte)) {
            // func(pte, *depth, custom);
        // }
    // }else{
        while (walk_next(vaddr, mepc, depth, &pte, &ptr_to_pte)) {}
    // }
    return pte;

    //old implementation below
/*
    uint64_t satp = CSRR(CSR_SATP);
    #if DEBUG_TAG == 1
        printSATP(satp);
    #endif

    int16_t current_depth;
    if ((satp & SATP64_MODE) >> 60 == SATP_MODE_SV39)
        current_depth = 2;
    else if ((satp & SATP64_MODE) >> 60 == SATP_MODE_SV48)
        current_depth = 3;
    else
        assert(0);

    PTE_64_Union* page_table = (PTE_64_Union*)((satp & SATP64_PPN) * RISCV_PGSIZE);

    for (; current_depth >= 0; current_depth--)
    {
        PTE_64_Union pte = page_table[getVPNpart(vaddr, current_depth)];
        #if DEBUG_TAG == 1
            printPTE(pte.raw_value, 1, current_depth);
        #endif

        if (!pte.pte.valid)
        {
            printtag_debug("Encountered invalid page (VA=0x%lx). Triggering Page-Fault...\n", vaddr);
            access_range_va(vaddr, PAGESIZE, mepc);
            assert(0);
        }

        if(func){
            func(pte, current_depth, custom);
        }

        if(PTE_TABLE(pte.raw_value)) { //TODO check if correct. previously this was PTE_TABLE(page_table->raw_value)
            page_table = (PTE_64_Union*)(pte.pte.ppn * (uint64_t)RISCV_PGSIZE);
        } else { //leaf
            if(depth){
                *depth = current_depth;
            }
            return pte;
        }
    }
    printtag_debug("Invalid Page Table. Did not find any a PTE.\n");
    assert(0);
    return (PTE_64_Union)(uint64_t)0;
*/
}


inline uintptr_t getPPN(uintptr_t vaddr, uintptr_t mepc, int16_t * depth, uint8_t* permissions)
{
    int16_t depth_tmp = -1;
    PTE_64_Union leaf = walk(vaddr, mepc, &depth_tmp, NULL, NULL);
    assert(leaf.pte.valid);
    assert(!PTE_TABLE(leaf.raw_value));
    if(depth){
        *depth = depth_tmp;
    }
    if (permissions != NULL)
    {
        *permissions = (leaf.pte.readable)        << 0  | 
                       (leaf.pte.writable         << 1) | 
                       (leaf.pte.executable       << 2) | 
                       (leaf.pte.user_accessible  << 3) |
                       (leaf.pte.global           << 4);
    }
    return leaf.pte.ppn;
}

inline uintptr_t PPNtoPPN4K(uintptr_t vaddr, uintptr_t ppn, int16_t depth)
{
    VA va = {.raw = vaddr};

    if(depth == PL_KILO){
        return ppn;
    }else if(depth == PL_MEGA){
        /*
        PTEntry* PT2  = SATP.PPN << 12;
        PTEntry  PTE2 = PT2[VPN[2]]; //points to 1G page or PT1
        PTEntry* PT1  = PTE2.PPN << 12;
        PTEntry  PTE1 = PT1[VPN[1]]; //points to 2M page
        PTE1.PPN will have the lowest 9 bits set to zero?
        PA = (PTE1.PPN << 12) + (VPN[0] << 12) + offset;
        PA = ((PTE1.PPN + VPN[0]) << 12) + offset;
        PPN = PTE1.PPN + VPN[0]
        */
        assert_ifdebug((ppn & 0x1FF) == 0);
        uintptr_t vpn0 = va.fields.vpn0; // = getVPNpart(addr, 0);
        return ppn + vpn0;
    }else{
        //TODO implement if/when someone uses gigapages
        printtag_error("Unsupported depth/page size.\n");
        assert(0);
        //probably: ppn + (va.fields.vpn1 << 9) + va.fields.vpn0;
    }
}

inline uintptr_t getPPN4K(uintptr_t vaddr, uintptr_t mepc)
{
    int16_t depth;
    uintptr_t ppn = getPPN(vaddr, mepc, &depth, NULL);
    ppn = PPNtoPPN4K(vaddr, ppn, depth);
    return ppn;
}

void init_walker(struct walk_ppns_t * data, uint64_t vaddr, uint64_t size){
    assert_ifdebug(data);
    memset(data, 0, sizeof(struct walk_ppns_t));
    data->init.vaddr = vaddr;
    data->init.size  = size;
}

bool walk_ppns(struct walk_ppns_t * data, uint64_t mepc){
    assert_ifdebug(data);
    if(data->init.size == 0){
        return 0;
    }
    uint64_t vaddr = 0;
    if(data->current.ppn == 0 && data->current.vpn == 0){
        //first run
        assert(IS_PAGE_ALIGNED(data->init.vaddr));
        assert(IS_PAGE_ALIGNED(data->init.size));
        vaddr = data->init.vaddr;
    }else{
        vaddr = (data->current.vpn + 1) << RISCV_PGSHIFT;
    }
    if(vaddr >= data->init.vaddr + data->init.size){
        //reached end
        data->init.size = 0;
        return 0;
    }

    int16_t depth;
    uint8_t permissions;
    uintptr_t ppn = getPPN(vaddr, mepc, &depth, &permissions);
    ppn = PPNtoPPN4K(vaddr, ppn, depth);
    data->current.vpn = vaddr >> RISCV_PGSHIFT;
    data->current.ppn = ppn;
    data->current.depth = depth;
    data->current.permissions = permissions;
    return true;
}
