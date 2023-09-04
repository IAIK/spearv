#ifndef TAG_H
#define TAG_H

#include "config.h"
#include "processor.h"
#include "memtracer.h"
#include "simif.h"
#include <vector>
#include "../riscv-pk/machine/tag_api.h"

//#define TAG_ADDR_ALIGN(addr) ((addr / tag_granularity_) * tag_granularity_)
#define TAG_ADDR_ALIGN(addr) (addr & (~(tag_granularity_-1)))

class tagging
{
public:
    tagging(simif_t* sim, processor_t* proc, size_t tag_width, size_t tag_granularity);
    ~tagging();

    bool get_tag(uint8_t mode, reg_t physical_addr, union memory_tag * tag_ptr, union memory_tag* mp_tag);

    bool mpk_match(uint16_t tag_mpk, access_type type);

    void tagcheck(bool virt, reg_t addr, reg_t physical_addr, reg_t pte, reg_t pte_level, reg_t len, access_type type, reg_t mode);


private:
    void get_tag_from_ppn(uint64_t tag_storage_base, uint8_t mode, reg_t ppn, union memory_tag * tag_ptr_host);
    processor_t* proc;
    simif_t* sim;
    friend class processor_t;
};

#endif
