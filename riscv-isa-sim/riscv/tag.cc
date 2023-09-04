#include "tag.h"
#include "decode.h"
#include "trap.h"
#include "common.h"
#include "config.h"
#include "processor.h"
#include "mmu.h"
#include <vector>

#define SPIKE 1
//#define printtag_debug INFO2
//#define printtag_debug2 INFO2
//#define printtag_debug_interrupt INFO2
//#define printtag_debug_interrupt2 INFO2

//#pragma GCC diagnostic push
//#pragma GCC diagnostic ignored "-Wwrite-strings"
#include "../riscv-pk/machine/tag_debug.h"
//#pragma GCC diagnostic pop

#define PTE_TO_TAG_PERMISSIONS(pte) (((pte) >> 1) & 0xf) /* previously 0x1f because g bit */

tagging::tagging(simif_t* sim, processor_t* proc, size_t tag_width, size_t tag_granularity)
 : sim(sim), proc(proc)
{
}

tagging::~tagging()
{
}

void tagging::get_tag_from_ppn(uint64_t tag_storage_base, uint8_t mode, reg_t ppn, union memory_tag * tag_ptr_host)
{
    assert(tag_ptr_host);
    //TODO DRAM_BASE is wrong if it was overwritten during startup. see make_mems in spike.cc. assert exists in spike.cc
    uint64_t tag_size_bytes = TAGMODE_TO_TAGBYTES(mode);
    uint64_t tag_addr = tag_storage_base + (ppn - this->proc->get_state()->tag_dram_base) * (tag_size_bytes);
    char* host_addr = sim->addr_to_mem(tag_addr);
    assert(host_addr);
    //TODO maybe from_target(*(target_endian<uint64_t>*)(host_addr + 0)));
    memset(tag_ptr_host, 0, sizeof(union memory_tag));

    if (mode == MTAG32) {
        tag_ptr_host->direct64[0] = 0;
        tag_ptr_host->direct64[1] = 0;
        tag_ptr_host->direct32[0] = *(uint32_t*)host_addr;
    } else if (mode == MTAG64) {
        tag_ptr_host->direct64[1] = 0;
        tag_ptr_host->direct64[0] = *(uint64_t*)host_addr;
    } else if (mode == MTAG128) {
        tag_ptr_host->direct64[0] = *(uint64_t*)(host_addr+0);
        tag_ptr_host->direct64[1] = *(uint64_t*)(host_addr+8);
    } else {
        assert(0);
    }
}

bool tagging::get_tag(uint8_t tag_mode, reg_t physical_addr, union memory_tag * tag_ptr, union memory_tag* mp_tag)
{
    //ERROR("get_tag mode=%d\n", tag_mode);
    if(tag_mode != MTAG32 && tag_mode != MTAG64 && tag_mode != MTAG128){
        assert(tag_mode == MTAG0); //TODO adapt everything below if more modes
        return false;
    }

/*
    //NOTE get mem size etc
    // size_of_tagstorage = num_physical_pages * 16
    // tag_storage_base = PM_START + mem_size - size_of_tagstorage
    uint64_t num_physical_pages = mem_size >> RISCV_PGSHIFT;
    uint64_t size_of_tagstorage = num_physical_pages * tag_size_bytes;
    uint64_t tag_storage_end = tag_storage_base + size_of_tagstorage;
*/

    reg_t ppn = physical_addr / 4096;
    uint64_t tag_storage_base = this->proc->get_state()->tag_storage_base;
    //INFO("Tag storage base: %lx\n", this->proc->get_state()->tag_storage_base);
    if(!tag_storage_base){
        //tag storage is not set-up yet.
        assert(false); //we should not get here, because mode should be set to MTAG0 in this case
        return false;
    }
    //TODO DRAM_BASE is wrong if it was overwritten during startup. see make_mems in spike.cc. assert exists in spike.cc
    uint64_t min_ppn = this->proc->get_state()->tag_dram_base;
    uint64_t max_ppn = (tag_storage_base / 4096) - 1; //assuming tag storage is on the upper end of the available memory
    if (ppn < min_ppn || ppn > max_ppn){
        //INFO("accessing memory that is not tagged. PA= %lx\n", physical_addr);
        return false;
    }

    get_tag_from_ppn(tag_storage_base, tag_mode, ppn, tag_ptr);
    // fetch megapage tag
    uint64_t megapage_ppn = ppn & ~(0x1ffull);
    get_tag_from_ppn(tag_storage_base, tag_mode, megapage_ppn, mp_tag);

    return true;
}

void _printInfo(reg_t addr, reg_t physical_addr, union memory_tag * tag){
    //INFO("pc = 0x%lx\n ", proc->get_state()->pc);
    INFO2("VA 0x%lx PA 0x%lx. tag: 0x%8lx 0x%8lx", addr, physical_addr, tag->direct64[1], tag->direct64[0]);
    INFO2(" [");
    printTagGeneric(tag, INFO2);
    INFO2("]");
    INFO2("\n");
}

bool tagging::mpk_match(uint16_t tag_mpk, access_type type)
{
    if (!proc)
        return false;

    mpkey_config_t * config = (mpkey_config_t *)&proc->get_state()->mpk_config;

    if (((tag_mpk == config->slot0_mpk) && ((type == STORE) ? !config->slot0_wd : true)) ||
        ((tag_mpk == config->slot1_mpk) && ((type == STORE) ? !config->slot1_wd : true)) ||
        ((tag_mpk == config->slot2_mpk) && ((type == STORE) ? !config->slot2_wd : true)) ||
        ((tag_mpk == config->slot3_mpk) && ((type == STORE) ? !config->slot3_wd : true)))
    {
        return true;
    }
    
    return false;
}

void tagging::tagcheck(bool virt, reg_t addr, reg_t physical_addr, reg_t pte, reg_t pte_level, reg_t len, access_type type, reg_t mode)
{
    //ERROR("tagcheck mode=%d\n", mode);
    if (!proc)
    {
        return;
    }
    
    reg_t prv = proc->get_state()->prv;
    //prv = mode;
   
    // Machine-mode bypasses all tag checks
    if (prv == PRV_M)
    {
        return;
    }

    uint8_t tag_mode = proc->get_state()->tag_mode;

    union memory_tag tag;
    union memory_tag mp_tag;
    if (!get_tag(tag_mode, physical_addr, &tag, &mp_tag))
    {
        return;
    }

    assert(tag_mode == MTAG32 || tag_mode == MTAG64 || tag_mode == MTAG128);

    uint64_t tag_control = proc->get_state()->tag_control;
    //if (pte_level != 0 && mp_tag.bit.hpce)
    //{
        //INFO("Trying to access huge page (pte_level = %ld) containing immutable or enclave pages. (NOT IMPLEMENTED because in HW we dont have huge page TLB entries)\n", pte_level);
        //the hardware, same as spike, also just fetches the respective 4k tag (in case the hpce bit is set for non 4k mappings)
        //_printInfo(addr, physical_addr, &tag);
        //_printInfo(addr, physical_addr  & ~(0x1fffffull), &mp_tag);
        //throw trap_hpce(virt, addr, 0, 0);
    //}
    if (!(tag_control & TAG_CTRL_DISABLE_IMM_WRITE_CHECK) && type == STORE && tag.bit.immutable)
    {
        ERROR("Cannot STORE on immutable page\n");
        _printInfo(addr, physical_addr, &tag);
        // TODO: throw trap immutable store fault
        throw trap_enclave_access(virt, addr, 0, 0);
    }

    uint64_t meid = proc->get_state()->meid;
    uint64_t eam = proc->get_state()->eam;
   
    if (tag.bit.page_type == PT_MONITOR)
    {
        ERROR("Cannot access PT_MONITOR\n");
        _printInfo(addr, physical_addr, &tag);
        throw trap_enclave_access(virt, addr, 0, 0);
    }

    reg_t satp = (virt) ? proc->get_state()->vsatp : proc->get_state()->satp;
    vm_info vm = decode_vm_info(proc->get_max_xlen(), false, mode, satp);
    uint64_t vpn_mask = (1 << (vm.levels * vm.idxbits)) - 1;

    //TODO make sure these checks are correct and same as the ones in cva6.

    // enclave accessing non-enclave page
    if (!(tag_control & TAG_CTRL_DISABLE_TAG_COMPARE_CHECKS) && (meid != 0 && tag.bit.page_type == PT_NORMAL))
    {
        if (eam == EAM_NORMAL)
        {
            return;
        } 
        else
        {
            ERROR("Enclave tried to access non-enclave page\n");
            throw trap_enclave_access(virt, addr, 0, 0); 
        }
    }
   
    // enclave checks 
    if (!(tag_control & TAG_CTRL_DISABLE_TAG_COMPARE_CHECKS) && (tag.bit.page_type == PT_ENCLAVE))
    {
        if (meid == 0)
        {
            ERROR("Non enclave tries to access enclave page\n");
            throw trap_enclave_access(virt, addr, 0, 0);
        }
        /*
        if (eam == EAM_NORMAL)
        {
            ERROR("Accessing enclave page but eam is not set\n");
            throw trap_enclave_access(virt, addr, 0, 0);
        }
        */
        if (meid != tag.bit.id)
        {
            ERROR("Enclave trying to access another enclave (meid mismatch)\n");
            throw trap_enclave_access(virt, addr, 0, 0);
        }

        if (tag_mode != MTAG32) {
            if (tag.bit.vpn != ((addr >> PGSHIFT) & vpn_mask))
            {
                ERROR("VPN for enclave page access doesn't match\n");
                throw trap_enc_integrity_fault(virt, addr, 0, 0);
            }
            if (tag.bit.pte_perms != PTE_TO_TAG_PERMISSIONS(pte))
            {
                ERROR("Permission bits for enclave page don't match\n");
                INFO("PPN: 0x%lx\n", physical_addr >> 12);
                INFO("TAG: 0x%x  - PTE: 0x%lx\n", tag.bit.pte_perms, PTE_TO_TAG_PERMISSIONS(pte));
                throw trap_enc_integrity_fault(virt, addr, 0, 0);
            }
        }
    }

    // mpk check
    if ((tag_mode == MTAG128) && !(tag_control & TAG_CTRL_DISABLE_TAG_COMPARE_CHECKS) && !mpk_match(tag.bit.mpk, type))
    {
        ERROR("MPKEY mismatch\n");
        throw trap_mpkey_mismatch(virt, addr, 0, 0);
    }
}
