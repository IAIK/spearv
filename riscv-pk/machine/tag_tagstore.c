#include "tag.h"
#include <string.h>
#include "flush.h"
#include "tag_debug.h"

uintptr_t max_ppn, min_ppn;

extern void tag_enclave_init();
void _write_tag_unchecked(union memory_tag* tag, uint64_t ppn, uint8_t mode);

#define is_in_range(addr, range_start_incl, range_end_excl) ((addr) >= (range_start_incl) && (addr) < (range_end_excl))

//TODO locking and tagmode etc regs must exist once per cpu or be propagated

static inline int _ppn_is_tagged(uintptr_t ppn){
    return (ppn >= min_ppn && ppn <= max_ppn);
}

static inline uint64_t ppn_to_tag_pa(uintptr_t ppn, uint8_t mode)
{
    assert(_ppn_is_tagged(ppn));
    uint64_t tag_storage_base = CSRR(CSR_U_TAG_STORAGE_BASE); 
    uint64_t dram_base_ppn = CSRR(CSR_U_TAG_DRAM_BASE);
    uint64_t tag_len = TAGMODE_TO_TAGBYTES(mode); // = CSRR(CSR_U_TAG_SIZE) / 8;
    uint64_t tag_addr = tag_storage_base + (ppn - dram_base_ppn) * tag_len;
    //printtag_debug("ppn_to_tag_pa tag_storage_base = %lx | tag_len = %d | ppn = %lx | tag_addr = %lx\n", tag_storage_base, tag_len, ppn, tag_addr);
    return tag_addr;
}

uint64_t get_max_tagstorage_size(uint64_t memory_size)
{
    uint64_t num_physical_pages = memory_size >> RISCV_PGSHIFT;
    uint64_t tag_size_in_bytes = 16; // max tag size = 128bit
    uint64_t size_of_tagstorage = num_physical_pages * tag_size_in_bytes;
    return size_of_tagstorage;
}

void tag_init(uint64_t dt_mem_base, uint64_t dt_mem_size, uint8_t mode, uint64_t tag_ctrl_flags)
{
    uint8_t initial_init = (dt_mem_base != 0) && (dt_mem_size != 0);

    if (initial_init) {
        printtag_debug("Initial tagging setup %lx %lx\n", dt_mem_base, dt_mem_size);
        assert(mem_base == dt_mem_base); //query_mem already sets this
        assert(mem_size == dt_mem_size); //query_mem already sets this
        mem_size_final = mem_size - get_max_tagstorage_size(mem_size + mem_base); // covers 0-ram_end
    } 
    
    assert((mode == MTAG0) || (mode == MTAG32) || (mode == MTAG64) || (mode == MTAG128));

    // nothing to do here
    if (initial_init && (mode == MTAG0))
    {
        printtag_debug("Init tagging with mode = MTAG0\n");
        CSRW(CSR_U_TAG_STORAGE_BASE, 0);
        CSRW(CSR_U_TAG_MODE, mode); 
        CSRW(CSR_U_TAG_DRAM_BASE, 0); // setting this to 0 so that we tag the entire memory range from 0 to ram-end
        //CSRW(CSR_U_TAG_DRAM_BASE, PM_START); // uncomment this to only tag RAM 
        return;
    }
   
    uint64_t tag_size_in_bytes = TAGMODE_TO_TAGBYTES(mode);
    uint64_t num_physical_pages = (mem_size + mem_base) >> RISCV_PGSHIFT;
    uint64_t size_of_tagstorage = num_physical_pages * tag_size_in_bytes;
    uint64_t tag_storage_base = (mode == MTAG0) ? 0 : (mem_base + mem_size - (size_of_tagstorage));
    uint64_t tag_storage_end = tag_storage_base + size_of_tagstorage;
    assert(PM_START == mem_base >> RISCV_PGSHIFT);
    assert((tag_storage_base & ~0xFFFULL) == tag_storage_base);
    //TODO assert that tag_storage_base is page aligned
    
    printtag_debug("mem size:           0x%x %d MB\n", mem_size, (mem_size/1024)/1024);
    printtag_debug("mem base:           0x%x %d MB\n", mem_base, (mem_base/1024)/1024);
    printtag_debug("tag_storage_base:   0x%x %d MB\n", tag_storage_base, (tag_storage_base/1024)/1024);
    printtag_debug("size_of_tagstorage: 0x%x %d MB\n", size_of_tagstorage, (size_of_tagstorage/1024)/1024);

    min_ppn = 0;
    max_ppn = -1;

    //CSRW(CSR_U_TAG_MODE, MTAG0); //disable tagging before messing with the tagstorage to be safe

    //initialize tag store:
    if (size_of_tagstorage > 0) {
        memset((char*)tag_storage_base, 0x00, size_of_tagstorage);
    }
    
    // disable immutable checks for page tables (otherwise ecreate must protect page tables!)
    //NOTE we set TAG_CTRL_NC_PTW_IN_E when entering/exiting
    if(tag_ctrl_flags){
        tag_ctrl_flags &= TAG_CTRL_DISABLE_IMM_PT_CHECKS | TAG_CTRL_DISABLE_TAG_COMPARE_CHECKS | TAG_CTRL_NC_PTW_IN_E | TAG_CTRL_DISABLE_IMM_WRITE_CHECK; //strip away invalid bits
    }else{
        tag_ctrl_flags = TAG_CTRL_DISABLE_IMM_PT_CHECKS; // | TAG_CTRL_NC_PTW_IN_E;
        if (mode == MTAG32 || mode == MTAG64 || mode == MTAG128){
            tag_ctrl_flags |= TAG_CTRL_DISABLE_TAG_COMPARE_CHECKS | TAG_CTRL_DISABLE_IMM_WRITE_CHECK;
        }
    }
    CSRW(CSR_U_TAG_CONTROL, tag_ctrl_flags);

    // write storage base to CSR
    CSRW(CSR_U_TAG_STORAGE_BASE, tag_storage_base);

    // enable tagging
    printtag_debug("Enable %ld bit memory tagging...\n", tag_size_in_bytes * 8);
    CSRW(CSR_U_TAG_MODE, mode); 
    printTagControl(tag_ctrl_flags);
    

    if (mode != MTAG0) {
        //self-protect tag store:
        //this works if the PPNs of the tagstore are also included in the tagstore
        //otherwise we'd need to fallback to PMP
        uint64_t tagstore_start_ppn = tag_storage_base>>RISCV_PGSHIFT;
        uint64_t tagstore_end_ppn   = tagstore_start_ppn + (ROUND_UP_PAGE(size_of_tagstorage)>>RISCV_PGSHIFT);

        printtag_debug("tagstore_start_ppn: %lx  ppn_to_tag_pa: %lx\n", tagstore_start_ppn, ppn_to_tag_pa(tagstore_start_ppn, mode));

        assert(is_in_range(ppn_to_tag_pa(tagstore_start_ppn, mode), tag_storage_base, tag_storage_end));
        assert(is_in_range(ppn_to_tag_pa(tagstore_end_ppn-1, mode), tag_storage_base, tag_storage_end));

        union memory_tag tag = {
            .bit.id = EID_INVALID,
            .bit.immutable = 1,
            //.bit.page_type = PT_MONITOR,
        };
        for (size_t ppn = tagstore_start_ppn; ppn < tagstore_end_ppn; ppn++)
        {
            _write_tag_unchecked(&tag, ppn, mode);
        }

        /*
        //PMP config to protect the tag storage

        //the below pmp protection works but isnt needed because tagstore can protect itself.
        //note: dont use pmp entries 0,1,2 because BBL (bbl.c) uses them to protect M stuff from the OS. (and minit.c uses entry 0 to allow access to everything)

        assert(0 == CSRR(CSR_PMPADDR3);
        uint64_t pmpcfg = CSRR(CSR_PMPCFG0);
        assert(pmpcfg & 0xFF000000 == 0);
        pmpcfg |= (PMP_NAPOT ) << (8*3); // only M mode can access this range
        uint64_t pmpaddr = (tag_storage_base | ((size_of_tagstorage - 1) >> 1)) >> PMP_SHIFT;
        printtag_debug("pmpaddr:            0x%x >> 2\n", pmpaddr << PMP_SHIFT);
        CSRW(CSR_PMPADDR0, pmpaddr);
        CSRW(CSR_PMPCFG0, pmpcfg);
        */

        //set min/max ppn after using ppn_to_tag_pa (otherwise assertion failure)
        min_ppn = (mem_base >> RISCV_PGSHIFT);
        max_ppn = (tag_storage_base >> RISCV_PGSHIFT) -1; /*min_ppn + num_physical_pages - 1;*/
    } 
    tag_enclave_init();
    flush_tlb_this_core();
    printtag_debug("tagstore init done\n");
}

bool read_tag(union memory_tag* tag, uintptr_t ppn)
{
    uint8_t mode = CSRR(CSR_U_TAG_MODE);
    //printtag_debug("tag read - mode = %d\n", mode);

    if(!_ppn_is_tagged(ppn) || (mode == MTAG0)){
        tag->direct64[0] = 0;
        tag->direct64[1] = 0;
        return false;
    }
    uint64_t tag_addr = ppn_to_tag_pa(ppn, mode);

    if (mode == MTAG32) {
        tag->direct64[0] = 0;
        tag->direct64[1] = 0;
        tag->direct32[0] = *(uint32_t*)tag_addr;
    } else if (mode == MTAG64) {
        tag->direct64[1] = 0;
        tag->direct64[0] = *(uint64_t*)tag_addr;
    } else if (mode == MTAG128) {
        tag->direct64[0] = *(uint64_t*)(tag_addr+0);
        tag->direct64[1] = *(uint64_t*)(tag_addr+8);
    } else {
        assert(0);
    }

    //printtag_debug("Read tag:  0x%lx %lx\n", tag->direct64[1], tag->direct64[0]);
    //printtag_debug("Read tag: "); printTag(tag); printtag_debug2("\n");
    return true;
}

void _write_tag_unchecked(union memory_tag* tag, uint64_t ppn, uint8_t mode)
{
    //printtag_debug("tag write - mode = %d\n", mode);
    uint64_t tag_addr = ppn_to_tag_pa(ppn, mode);

    if (mode == MTAG32) {
        *(uint32_t*)tag_addr = tag->direct32[0];
    } else if (mode == MTAG64) {
        *(uint64_t*)tag_addr = tag->direct64[0];
    } else if (mode == MTAG128) {
        *(uint64_t*)(tag_addr+0) = tag->direct64[0];
        *(uint64_t*)(tag_addr+8) = tag->direct64[1];
    } else {
        assert(0);
    }

    //printtag_debug("Write tag: 0x%lx %lx\n", tag->direct64[1], tag->direct64[0]);
    //printtag_debug("Write tag: "); printTag(tag); printtag_debug2("\n");

    flush_tlb_ppn(ppn);
}

bool write_tag(union memory_tag* tag, uint64_t ppn)
{
    uint8_t mode = CSRR(CSR_U_TAG_MODE);

    if(!_ppn_is_tagged(ppn) || (mode == MTAG0)){
        return false;
    }

    _write_tag_unchecked(tag, ppn, mode);
    return true;
}
