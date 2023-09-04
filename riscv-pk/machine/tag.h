#include "unprivileged_memory.h"
#include "mtrap.h"
#include "emulation.h"
#include <limits.h>
#include <stdbool.h>

#include "tag_api.h"

//------------------------------------------------------------------------------
#define HERE() printtag_error("%s:%d\n", __FUNCTION__, __LINE__)

#define DEBUG_PREFIX "[SM] "
#define printtag_error(fmt_str, ...)             do { printm(COLOR_RED    DEBUG_PREFIX fmt_str COLOR_RESET, ##__VA_ARGS__); } while (0)
#define printtag_warning(fmt_str, ...)           do { printm(COLOR_YELLOW DEBUG_PREFIX fmt_str COLOR_RESET, ##__VA_ARGS__); } while (0)
#define printtag_always(fmt_str, ...)            do { printm(COLOR_RESET  DEBUG_PREFIX fmt_str COLOR_RESET, ##__VA_ARGS__); } while (0)
#define printtag_debug(fmt_str, ...)             do { printm(COLOR_CYAN   DEBUG_PREFIX fmt_str COLOR_RESET, ##__VA_ARGS__); } while (0)
#define printtag_debug_interrupt(fmt_str, ...)   do { printm(COLOR_YELLOW DEBUG_PREFIX fmt_str COLOR_RESET, ##__VA_ARGS__); } while (0)
#define printtag_debug_interrupt2(fmt_str, ...)  do { printm(COLOR_YELLOW ""           fmt_str COLOR_RESET, ##__VA_ARGS__); } while (0)
#define printtag_debug2(fmt_str, ...)            do { printm(COLOR_CYAN   ""           fmt_str COLOR_RESET, ##__VA_ARGS__); } while (0)
#define printtag_always2(fmt_str, ...)           do { printm(COLOR_RESET  ""           fmt_str COLOR_RESET, ##__VA_ARGS__); } while (0)
//#define printm_debug(...)  printm(__VA_ARGS__)

#if DEBUG_TAG == 1
  #define assert_ifdebug assert
#else
  #define assert_ifdebug(arg) do {} while (0)
  #undef printtag_debug
  #undef printtag_debug_interrupt
  #undef printtag_debug_interrupt2
  #undef printtag_debug2
  //#undef printm_debug
  #define printtag_debug(fmt_str, ...) do {} while (0)
  #define printtag_debug2(fmt_str, ...) do {} while (0)
  #define printtag_debug_interrupt(fmt_str, ...) do {} while (0)
  #define printtag_debug_interrupt2(fmt_str, ...) do {} while (0)
  //#define printm_debug(fmt_str, ...) do {} while (0)
#endif

#define PML4_MASK 0x0000ff8000000000ULL
#define PML3_MASK 0x0000007fc0000000ULL
#define PML2_MASK 0x000000003fe00000ULL
#define PML1_MASK 0x00000000001ff000ULL

#define PM_START 0x80000

#define PMP_SKIP_TAG 0x20

#define EID_INVALID (((uint64_t)1<<16) - 1)

typedef union
{
    uint64_t raw;
    struct
    {
        uint16_t offset         : 12;
        uint16_t vpn0           :  9;
        uint16_t vpn1           :  9;
        uint16_t vpn2           :  9;
        uint16_t vpn3           :  9; //for Sv48
        uint64_t unused         : 16;
    } __attribute__((__packed__)) fields;
} VA;


typedef struct
{
    uint64_t valid           : 1;
    uint64_t readable        : 1;
    uint64_t writable        : 1;
    uint64_t executable      : 1;
    uint64_t user_accessible : 1;
    uint64_t global          : 1;
    uint64_t accessed        : 1;
    uint64_t dirty           : 1;
    uint64_t rsw             : 2;
    uint64_t ppn             : 44;
    uint64_t reserved        : 10;
} __attribute__((__packed__)) PTE_64;

typedef union
{
    uint64_t raw_value;
    PTE_64 pte;
} PTE_64_Union;

typedef struct sm_thread_regs_t {
    //NOTE: using the same structure and ordering as in mentry.S !
    //normal regs:
    //uint64_t _unused;
    uint64_t ra;
    uint64_t sp;
    uint64_t gp;
    uint64_t tp;
    uint64_t t0;
    uint64_t t1;
    uint64_t t2;
    uint64_t s0;
    uint64_t s1;
    uint64_t a0;
    uint64_t a1;
    uint64_t a2;
    uint64_t a3;
    uint64_t a4;
    uint64_t a5;
    uint64_t a6;
    uint64_t a7;
    uint64_t s2;
    uint64_t s3;
    uint64_t s4;
    uint64_t s5;
    uint64_t s6;
    uint64_t s7;
    uint64_t s8;
    uint64_t s9;
    uint64_t s10;
    uint64_t s11;
    uint64_t t3;
    uint64_t t4;
    uint64_t t5;
    uint64_t t6;
    uint64_t _padding_todo_remove_maybe;
} sm_thread_regs_t;

typedef struct csrs_t {
    uint64_t eam;
    uint64_t tcs;
    uint64_t mtvec;
    uint64_t mideleg;
    uint64_t medeleg;
    //TODO stvec?
    //TODO mie?
} csrs_t;

typedef enum
{
    STATE_UNINITIALIZED = 0,
    STATE_TEARDOWN,
    STATE_READY,
    STATE_ENTERED,
} e_state;


typedef struct e_tcs_t {
    //sm_type_and_tstate state;
    //sm_secs_t * secs;
    uint64_t stack;
    uint64_t stack_size;
    sm_thread_regs_t regs_enclave;
    sm_thread_regs_t regs_host;
    csrs_t csrs_enclave;
    csrs_t csrs_host;

    uint64_t mepc_eenter; //mepc at first eenter.
    uint64_t mepc_interrupt; //mepc at interrupt.
    uint64_t mpp;
} e_tcs_t;

struct e_metapage;
typedef enum
{
    SHM_OWNER = 0,
    SHM_RECEIVER = 1,
} shared_key_state;
typedef struct shared_key
{
    uint16_t key_id;                //Id of the enclave sharing the key
    struct e_metapage *metapage_pa;        //Pointer to the receiving SECS structure.
    shared_key_state state;         //Flag determining the 
} shared_key;

typedef struct e_metapage
{
    size_t                   parent_id; // zero or id of parent enclave
    size_t                   id;
    uint64_t                 entry;
    size_t                   codesize;
    e_state                  state;
    e_tcs_t                  tcs; //TODO should be per-thread if multi-threaded
    uint64_t                 satp;
    ecreate_args_t *         ecreate_args_va;
    size_t                   mapped_pages; //excl SECS/TCSs?
    size_t                   mapped_pages_init; //excl SECS/TCSs?
    //spinlock_t lock; // TODO lock enclave structure if multi-core system!
    uint64_t                 desired_time;
    uint64_t                 irq_cnt;
    uint64_t                 irq_delegation_ticks;
    uint64_t                 irq_return_ticks; 
    struct e_metapage*       current_child_status_page;
    struct e_metapage*       root_parent_status_page;
    struct e_metapage*       parent_status_page;
    struct shared_key        sharing_array[64];
    uint64_t                 child_ctr; 
} e_metapage;

static void print_e_metapage(e_metapage* metapage){
    printtag_always("metapage = %lx\n", metapage);
    printtag_always("  parent_id                 = 0x%lx\n", metapage->parent_id);
    printtag_always("  id                        = 0x%lx\n", metapage->id);
    printtag_always("  entry                     = 0x%lx\n", metapage->entry);
    printtag_always("  codesize                  = 0x%lx\n", metapage->codesize);
    printtag_always("  state                     = 0x%lx\n", metapage->state);
    printtag_always("  tcs                       = 0x%lx\n", metapage->tcs);
    printtag_always("  satp                      = 0x%lx\n", metapage->satp);
    printtag_always("  ecreate_args_va           = 0x%lx\n", metapage->ecreate_args_va);
    printtag_always("  mapped_pages              = 0x%lx\n", metapage->mapped_pages);
    printtag_always("  mapped_pages_init         = 0x%lx\n", metapage->mapped_pages_init);
    printtag_always("  desired_time              = 0x%lx\n", metapage->desired_time);
    printtag_always("  irq_cnt                   = 0x%lx\n", metapage->irq_cnt);
    printtag_always("  irq_delegation_ticks      = 0x%lx\n", metapage->irq_delegation_ticks);
    printtag_always("  irq_return_ticks          = 0x%lx\n", metapage->irq_return_ticks);
    printtag_always("  current_child_status_page = 0x%lx\n", metapage->current_child_status_page);
    printtag_always("  root_parent_status_page   = 0x%lx\n", metapage->root_parent_status_page);
    printtag_always("  parent_status_page        = 0x%lx\n", metapage->parent_status_page);
    printtag_always("  child_ctr                 = 0x%lx\n", metapage->child_ctr);
}




// main trap handler
void trap_m_call(uintptr_t* _regs, insn_t insn, uintptr_t mcause, uintptr_t mepc, uintptr_t mstatus);

// individual trap functions
static void trap_ecreate(sm_thread_regs_t* regs, uintptr_t mepc);
static void trap_eenter(sm_thread_regs_t* regs, uintptr_t mepc);
static void trap_eexit(sm_thread_regs_t* regs, uintptr_t mepc);
static void trap_edestroy(sm_thread_regs_t* regs, uintptr_t mepc);
// loads partial tag for given virtual address and offset and returns it to U-mode
static uintptr_t trap_ltag(sm_thread_regs_t* regs, uintptr_t mepc);
static void trap_ltag2(sm_thread_regs_t* regs, uintptr_t mepc);
// stores tag for given virtual address
static void trap_stag(sm_thread_regs_t* regs, uintptr_t mepc);
// locks entire page translation for given virtual address by setting WD, PL, PT and E bits
static void trap_ppage(sm_thread_regs_t* regs, uintptr_t mepc);
static void trap_eadd(sm_thread_regs_t* regs, uintptr_t mepc);
static void trap_eremove(sm_thread_regs_t* regs, uintptr_t mepc);
static void trap_tagreset(sm_thread_regs_t* regs, uintptr_t mepc);
static void trap_debug(sm_thread_regs_t* regs, uintptr_t mepc);
static void trap_set_fence(sm_thread_regs_t* regs, uintptr_t mepc);

static void ppage(uintptr_t vaddr, int64_t prot, uintptr_t mepc, uintptr_t vaddr_range_start, uintptr_t vaddr_range_end);


//tag-storage:
bool read_tag(union memory_tag* tag, uintptr_t ppn);
bool write_tag(union memory_tag* tag, uintptr_t ppn);
void tag_init(uint64_t dt_mem_base, uint64_t dt_mem_size, uint8_t mode, uint64_t tag_ctrl_flags);
uint64_t get_max_tagstorage_size(uint64_t memory_size);

//helper functions:
static void store_regs(sm_thread_regs_t* src, e_metapage* dst, uintptr_t mepc);
static void restore_regs(sm_thread_regs_t* dst, e_metapage* src, uintptr_t mepc);
static void printPTE(uint64_t pte, int print_tag, int16_t depth);
static void printregs(sm_thread_regs_t* reg_state);

//virtual memory:
int walk_next(uintptr_t vaddr, uintptr_t mepc, int16_t * depth, PTE_64_Union * current_pte, PTE_64_Union ** ptr_to_current_pte);
PTE_64_Union walk(uintptr_t vaddr, uintptr_t mepc, int16_t * depth, void* custom, void (*func)(PTE_64_Union, int16_t, void*));
// void visit_all_PTEs_in_PT(PTE_64_Union current_pte, int16_t depth, uint64_t vaddr_to_ignore, void* custom, bool (*func)(PTE_64_Union*, size_t, PTE_64_Union, int16_t, void*));

void access_range_va(uint64_t vaddr, uint64_t size, uint64_t mepc);
uintptr_t getPPN(uintptr_t vaddr, uintptr_t mepc, int16_t * depth, uint8_t* permissions);
uintptr_t getPPN4K(uintptr_t vaddr, uintptr_t mepc);
uintptr_t PPNtoPPN4K(uintptr_t vaddr, uintptr_t ppn, int16_t depth);
struct walk_ppns_t {
    struct {
        uint64_t vaddr;
        uint64_t size;
    } init;
    struct {
        uint64_t vpn;
        uint64_t ppn;
        int16_t depth;
        uint8_t permissions;
    } current;
    struct {

    } _internal;
};
bool walk_ppns(struct walk_ppns_t * data, uint64_t mepc);
void init_walker(struct walk_ppns_t * data, uint64_t vaddr, uint64_t size);

uint16_t getVPNpart(uintptr_t vaddr, uint8_t vpn_index);
// uint64_t getVPNpartMask(uint8_t vpn_index);


static inline void fast_memset(
    void * paddr_target, 
    uint64_t constant, 
    size_t length_in_bytes)
{
    assert_ifdebug(length_in_bytes > 0);
    assert_ifdebug(length_in_bytes % 64 == 0);
    assert_ifdebug((uint64_t)paddr_target % 64 == 0);
    assert_ifdebug((((uint64_t)paddr_target+length_in_bytes-1) >> 12) == ((uint64_t)paddr_target >> 12));
    register uintptr_t __target = (uintptr_t)paddr_target;
    register uintptr_t __target_end = (uintptr_t)paddr_target + length_in_bytes;
    asm volatile (//set (double)word
                  "1:\n"
                  "sd %[__constant], 0*8(%[__target])\n"
                  "sd %[__constant], 1*8(%[__target])\n"
                  "sd %[__constant], 2*8(%[__target])\n"
                  "sd %[__constant], 3*8(%[__target])\n"
                  "sd %[__constant], 4*8(%[__target])\n"
                  "sd %[__constant], 5*8(%[__target])\n"
                  "sd %[__constant], 6*8(%[__target])\n"
                  "sd %[__constant], 7*8(%[__target])\n"
                  //increment target and loop until target == __target_end
                  "addi %[__target], %[__target], 8*8\n"
                  "bltu %[__target], %[__target_end], 1b\n"
                  : /* output */
                    [__target] "+r" (__target)
                  : /* input */
                    [__target_end] "r" (__target_end), 
                    [__constant] "r"(constant)
    );
}
