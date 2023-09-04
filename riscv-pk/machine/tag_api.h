#pragma once

#include <stdint.h> //for uint64_t

// -- config start -------------------------------------------------------------
#if ! defined(DEBUG_TAG)
    //#pragma message "DEBUG_TAG is not defined. setting it to its default value."
    #define DEBUG_TAG 1
#endif
#define DEBUG_CSRW 1 
#define DEBUG_FDT 0
#define DEBUG_FDT_TREE 0

#if ! defined(SM_TAG_MEGAPAGES)
    #define SM_TAG_MEGAPAGES 0
#endif
// -- config end ---------------------------------------------------------------


#define API_RET_FAILED -1
#define API_RET_SUCCESS 0
//ids for machine-mode functions for our new "instruction"
#define LTAG             0
#define STAG             1
#define PPAGE            2
#define ECREATE          3
#define EENTER           4
#define EEXIT            5
#define EDESTROY         6
#define LTAG2            7
#define EADD             8
#define EREMOVE          9
#define TAGRESET        10
#define API_DEBUG       11
#define API_SET_FENCE   12
#define SHM_CREATE      13
#define SHM_ACK         14
#define SHM_DESTROY     15


//#define PAGESIZE RISCV_PGSIZE
#define PAGESIZE 4096

#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_GRAY    "\x1b[90m"
#define COLOR_RESET   "\x1b[0m"

static inline const char * _csr_to_str(uint64_t csr_id) {
    switch (csr_id)
    {
        #define DECLARE_CSR(name, num) case num: return #name;
        #include "encoding.h"
        #undef DECLARE_CSR
        default:
        {
            return "_UNKNOWN_CSR_";
        }
    }
}

//#define OLD_CSRR(csr_name) ({uint64_t ret; asm volatile ("csrr %0, "csr_name : "=r"(ret)); ret;})
#define __CSRR(csr_id) ({uint64_t ret; asm volatile ("csrr %0, %1" : "=r"(ret) : "i"(csr_id)); ret;})
//#define __CSRRW(csr_id, val) ({uint64_t ret; asm volatile ("csrrw %0, %1, %2" : "=r"(ret) : "i"(csr_id), "r"((uint64_t)val)); ret;})
#define __CSRW(csr_id, val) do {asm volatile ("csrw %0, %1" : : "i"(csr_id), "r"((uint64_t)val));} while (0)
#define __CSR_SET(csr_id, val) do {asm volatile ("csrs %0, %1" : : "i"(csr_id), "r"((uint64_t)val));} while (0)
#define __CSR_CLEAR(csr_id, val) do {asm volatile ("csrc %0, %1" : : "i"(csr_id), "r"((uint64_t)val));} while (0)

#if DEBUG_TAG == 1 && DEBUG_CSRW == 1 && defined(printtag_debug)
#define CSRR __CSRR
#define CSRW(csr_id, val) do { printtag_debug("CSRW %s = 0x%lx " COLOR_GRAY "(previous value: 0x%lx)\n", _csr_to_str(csr_id), val, __CSRR(csr_id)); __CSRW(csr_id, val); } while (0)
#define CSR_SET(csr_id, val) do { printtag_debug("CSR_SET %s = 0x%lx\n", _csr_to_str(csr_id), val); __CSR_SET(csr_id, val); } while (0)
#define CSR_CLEAR(csr_id, val) do { printtag_debug("CSR_CLEAR %s = 0x%lx\n", _csr_to_str(csr_id), val); __CSR_CLEAR(csr_id, val); } while (0)
#else
#define CSRR __CSRR
#define CSRW __CSRW
#define CSR_SET __CSR_SET
#define CSR_CLEAR __CSR_CLEAR
#endif

//#define READ_REG(register) ({uint64_t reg; asm volatile("mv %0, "#register : "=r"(reg)); reg;})
#define ROUND_UP_TO_POWEROFTWO(number, multiple) (((number) + (multiple) - 1) & -(multiple)) 
#define ROUND_UP_PAGE(number) ROUND_UP_TO_POWEROFTWO(number, PAGESIZE)
#define ROUND_DOWN_PAGE(addr) ((addr) & ~(RISCV_PGSIZE-1))
#define IS_PAGE_ALIGNED(addr) (ROUND_DOWN_PAGE(addr) == (addr))

#define ROUND_UP_2MPAGE(number) ROUND_UP_TO_POWEROFTWO(number, (RISCV_PGSIZE<<9))
#define ROUND_DOWN_2MPAGE(addr) ((addr) & ~((RISCV_PGSIZE<<9)-1))

#define TAGMODE_TO_TAGBYTES(mode) (((mode) == MTAG0) ? 0 : ((mode) == MTAG32) ? 4 : ((mode) == MTAG64) ? 8 : 16)

// =============================================================================
// TODO KEEP THESE VALUES/STRUCTS ALIGNED WITH cva6/include/riscv_pkg.sv AT ALL TIMES

//values for CSR_U_TAG_CONTROL:
#define TAG_CTRL_DISABLE_TAG_COMPARE_CHECKS       (1 << 0)
#define TAG_CTRL_DISABLE_IMM_PT_CHECKS            (1 << 1)
#define TAG_CTRL_NC_PTW_IN_E                      (1 << 2)
#define TAG_CTRL_DISABLE_IMM_WRITE_CHECK          (1 << 3)

typedef enum {
  MTAG0   = 0,
  MTAG32  = 1,
  MTAG64  = 2,
  MTAG128 = 3,
} TagMode;

typedef enum {
  EAM_NORMAL   = 0,
  EAM_SHM      = 1,
  EAM_ENCLAVE  = 2, // NOTE: doesnt really exist anymore, but hw code needs it.
  EAM_FUTURE2  = 3,
} EnclaveAccessMode;

typedef enum {
  PT_NORMAL    = 0,
  PT_ENCLAVE   = 1,
  PT_MONITOR   = 2,
  PT_SHARED    = 3,
  PT_PAGETABLE = 4, // PT_PAGETABLE
  PT_FUTURE2   = 5,
  PT_FUTURE3   = 6,
  PT_FUTURE4   = 7,
} PageType;

typedef enum {
  PL_KILO    = 0, //4KiB
  PL_MEGA    = 1, //2MiB
  PL_GIGA    = 2, //1GiB
  PL_INVALID = 3,
} PageLevel;

union memory_tag {
    //note that everything apart from VPN and pte_perms fits in the lowest 32 bit
    /*
    struct __attribute__((__packed__)) {
      //1st word:
      uint16_t  id           : 16;
      PageType  page_type    :  3;
      uint8_t   hpce         :  1;
      PageLevel page_level   :  2;
      uint8_t   validated    :  1;
      uint8_t   immutable    :  1;
      uint8_t   future       :  8;
      uint32_t  __na__[3];
    } bit_mtag32;
    */
    struct __attribute__((__packed__)) {
      //note that everything apart from VPN and pte_perms fits in the lowest 32 bit
      //1st word:
      uint16_t  id           : 16;
      PageType  page_type    :  3;
      uint8_t   hpce         :  1;
      PageLevel page_level   :  2;
      uint8_t   validated    :  1;
      uint8_t   immutable    :  1;
      uint64_t  vpn          : 36;
      uint8_t   pte_perms    :  4; //same as PTE_U,PTE_X,PTE_W,PTE_R from encoding.h but right-shifted by 1 bit since we dont need the 0th valid-bit (previously 5 bits with PTE_G as MSB)
      //2nd word:
      uint16_t  mpk          : 10;
      uint64_t  unused       : 54;
    } bit;
    uint64_t direct64[2];
    uint32_t direct32[4];
};

typedef struct __attribute__((__packed__)){
    uint8_t  slot3_wd    :  1; 
    uint16_t slot3_mpk   : 10; 
    uint8_t  slot2_wd    :  1; 
    uint16_t slot2_mpk   : 10; 
    uint8_t  slot1_wd    :  1; 
    uint16_t slot1_mpk   : 10; 
    uint8_t  slot0_wd    :  1; 
    uint16_t slot0_mpk   : 10; 
} mpkey_config_t;

union mpkey_config {
    mpkey_config_t bit;
    uint64_t direct;
};

// =============================================================================

typedef struct {
    uint64_t desired_time;
    uint64_t enclave_code_entry;
    uint64_t out_irq_cnt;
    uint64_t out_irq_delegation_ticks;
    uint64_t out_irq_return_ticks;
    uint64_t do_ppage;
    uint64_t unused[15];
} ecreate_args_t;

#define ourthing_7(a0, a1, a2, a3, a4, a5, a6)                        \
({                                                                    \
    register unsigned long _a0 asm("a0") = (unsigned long)(a0);       \
    register unsigned long _a1 asm("a1") = (unsigned long)(a1);       \
    register unsigned long _a2 asm("a2") = (unsigned long)(a2);       \
    register unsigned long _a3 asm("a3") = (unsigned long)(a3);       \
    register unsigned long _a4 asm("a4") = (unsigned long)(a4);       \
    register unsigned long _a5 asm("a5") = (unsigned long)(a5);       \
    register unsigned long _a6 asm("a6") = (unsigned long)(a6);       \
    asm volatile(".word 0x7b;"                                        \
            : "+r"(_a0)                                               \
            : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5), "r"(_a6) \
            : "memory");                                              \
    _a0;                                                              \
})

#define ourthing_6(a0, a1, a2, a3, a4, a5)                            \
({                                                                    \
    register unsigned long _a0 asm("a0") = (unsigned long)(a0);       \
    register unsigned long _a1 asm("a1") = (unsigned long)(a1);       \
    register unsigned long _a2 asm("a2") = (unsigned long)(a2);       \
    register unsigned long _a3 asm("a3") = (unsigned long)(a3);       \
    register unsigned long _a4 asm("a4") = (unsigned long)(a4);       \
    register unsigned long _a5 asm("a5") = (unsigned long)(a5);       \
    asm volatile(".word 0x7b;"                                        \
            : "+r"(_a0)                                               \
            : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5)        \
            : "memory");                                              \
    _a0;                                                              \
})

#define ourthing_5(a0, a1, a2, a3, a4)                                \
({                                                                    \
    register unsigned long _a0 asm("a0") = (unsigned long)(a0);       \
    register unsigned long _a1 asm("a1") = (unsigned long)(a1);       \
    register unsigned long _a2 asm("a2") = (unsigned long)(a2);       \
    register unsigned long _a3 asm("a3") = (unsigned long)(a3);       \
    register unsigned long _a4 asm("a4") = (unsigned long)(a4);       \
    asm volatile(".word 0x7b;"                                        \
            : "+r"(_a0)                                               \
            : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4)                  \
            : "memory");                                              \
    _a0;                                                              \
})

#define ourthing_4(a0, a1, a2, a3)                                    \
({                                                                    \
    register unsigned long _a0 asm("a0") = (unsigned long)(a0);       \
    register unsigned long _a1 asm("a1") = (unsigned long)(a1);       \
    register unsigned long _a2 asm("a2") = (unsigned long)(a2);       \
    register unsigned long _a3 asm("a3") = (unsigned long)(a3);       \
    asm volatile(".word 0x7b;"                                        \
            : "+r"(_a0)                                               \
            : "r"(_a1), "r"(_a2), "r"(_a3)                            \
            : "memory");                                              \
    _a0;                                                              \
})

#define ourthing_3(a0, a1, a2)                                        \
({                                                                    \
    register unsigned long _a0 asm("a0") = (unsigned long)(a0);       \
    register unsigned long _a1 asm("a1") = (unsigned long)(a1);       \
    register unsigned long _a2 asm("a2") = (unsigned long)(a2);       \
    asm volatile(".word 0x7b;"                                        \
            : "+r"(_a0)                                               \
            : "r"(_a1), "r"(_a2)                                      \
            : "memory");                                              \
    _a0;                                                              \
})

#define ourthing_2(a0, a1)                                            \
({                                                                    \
    register unsigned long _a0 asm("a0") = (unsigned long)(a0);       \
    register unsigned long _a1 asm("a1") = (unsigned long)(a1);       \
    asm volatile(".word 0x7b;"                                        \
            : "+r"(_a0)                                               \
            : "r"(_a1)                                                \
            : "memory"); /* TODO a1 may be a return value */          \
    _a0;                                                              \
})

//TODO clobber a1? (only ltag2 seems to need it?)
#define ourthing_1(a0)                                                \
({                                                                    \
    register unsigned long _a0 asm("a0") = (unsigned long)(a0);       \
    asm volatile(".word 0x7b;"                                        \
            : "+r"(_a0)                                               \
            :                                                         \
            : "memory");                                              \
    _a0;                                                              \
})

#define api_stag(vaddr, tagl, tagh)                                     ourthing_4(STAG, vaddr, tagl, tagh)
#define api_share(secs_source, va_start, va_end, secs_receiver)         ourthing_5(SHM_CREATE, secs_source, va_start, va_end, secs_receiver)
#define api_share_ack()                                                 ourthing_1(SHM_ACK /*TODO*/)
#define api_share_destroy()                                             ourthing_1(SHM_DESTROY /*TODO*/)
#define api_ltag(vaddr, offset)                                         ourthing_3(LTAG, vaddr, offset)
#define api_ppage(vaddr, prot)                                          ourthing_3(PPAGE, vaddr, prot)
//#define api_eenter(statuspage)                                          ourthing_2(EENTER, statuspage)
#define api_eenter(statuspage)                                          ({int retval; retval = ourthing_2(EENTER, statuspage); retval;})
#define api_eexit()                                                     ourthing_1(EEXIT)
#define api_eremove(statuspage, vaddr, size, prot)                      ourthing_5(EREMOVE, statuspage, vaddr, size, prot)
#define api_eadd(statuspage, vaddr, size, prot, zero_mem)               ourthing_6(EADD, statuspage, vaddr, size, prot, zero_mem)
#define api_edestroy(statuspage)                                        ourthing_2(EDESTROY, statuspage)
#define api_debug()                                                     ourthing_1(API_DEBUG)
#define api_set_fence(flags)                                            ourthing_2(API_SET_FENCE, flags)


#define api_ecreate(statuspage, stack, stacksize, entry, codesize) ourthing_7(ECREATE, statuspage, stack, stacksize, entry, codesize, NULL)
#define api_ecreate2(statuspage, stack, stacksize, entry, codesize, others) ourthing_7(ECREATE, statuspage, stack, stacksize, entry, codesize, others)
#define api_tagreset(mode)                   ourthing_3(TAGRESET, mode, 0)
#define api_tagreset2(mode, tag_ctrl_flags)  ourthing_3(TAGRESET, mode, tag_ctrl_flags)
static inline void api_ltag2(void * vaddr, union memory_tag * tag_ptr){
    register unsigned long _a0 asm("a0") = LTAG2;
    register unsigned long _a1 asm("a1") = (unsigned long)(vaddr);
    asm volatile(".word 0x7b;"
            : "+r"(_a0), "+r"(_a1)
            : 
            : "memory");
    tag_ptr->direct64[0] = _a0;
    tag_ptr->direct64[1] = _a1;
}

