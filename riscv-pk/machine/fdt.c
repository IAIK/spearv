// See LICENSE for license details.

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "config.h"
#include "fdt.h"
#include "mtrap.h"
#include "tag.h"

#define print_always(fmt_str, ...) do { printm(COLOR_MAGENTA "[FDT] " fmt_str COLOR_RESET, ##__VA_ARGS__); } while (0)
#if defined(DEBUG_FDT) && DEBUG_FDT == 1
#define print_debug print_always
#else
#define print_debug(fmt_str, ...) do {} while (0)
#endif

static inline uint32_t bswap(uint32_t x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  uint32_t y = (x & 0x00FF00FF) <<  8 | (x & 0xFF00FF00) >>  8;
  uint32_t z = (y & 0x0000FFFF) << 16 | (y & 0xFFFF0000) >> 16;
  return z;
#else
  /* No need to swap on big endian */
  return x;
#endif
}

static inline int isstring(char c)
{
  if (c >= 'A' && c <= 'Z')
    return 1;
  if (c >= 'a' && c <= 'z')
    return 1;
  if (c >= '0' && c <= '9')
    return 1;
  if (c == '\0' || c == ' ' || c == ',' || c == '-')
    return 1;
  return 0;
}

static uint32_t *fdt_scan_helper(
  uint32_t *lex,
  const char *strings,
  struct fdt_scan_node *node,
  const struct fdt_cb *cb)
{
  struct fdt_scan_node child;
  struct fdt_scan_prop prop;
  int last = 0;

  child.parent = node;
  // these are the default cell counts, as per the FDT spec
  child.address_cells = 2;
  child.size_cells = 1;
  prop.node = node;

  while (1) {
    switch (bswap(lex[0])) {
      case FDT_NOP: {
        lex += 1;
        break;
      }
      case FDT_PROP: {
        assert (!last);
        prop.name  = strings + bswap(lex[2]);
        prop.len   = bswap(lex[1]);
        prop.value = lex + 3;
        if (node && !strcmp(prop.name, "#address-cells")) { node->address_cells = bswap(lex[3]); }
        if (node && !strcmp(prop.name, "#size-cells"))    { node->size_cells    = bswap(lex[3]); }
        lex += 3 + (prop.len+3)/4;
        cb->prop(&prop, cb->extra);
        break;
      }
      case FDT_BEGIN_NODE: {
        uint32_t *lex_next;
        if (!last && node && cb->done) cb->done(node, cb->extra);
        last = 1;
        child.name = (const char *)(lex+1);
        if (cb->open) cb->open(&child, cb->extra);
        lex_next = fdt_scan_helper(
          lex + 2 + strlen(child.name)/4,
          strings, &child, cb);
        if (cb->close && cb->close(&child, cb->extra) == -1)
          while (lex != lex_next) *lex++ = bswap(FDT_NOP);
        lex = lex_next;
        break;
      }
      case FDT_END_NODE: {
        if (!last && node && cb->done) cb->done(node, cb->extra);
        return lex + 1;
      }
      default: { // FDT_END
        if (!last && node && cb->done) cb->done(node, cb->extra);
        return lex;
      }
    }
  }
}

void fdt_scan(uintptr_t fdt, const struct fdt_cb *cb)
{

  struct fdt_header *header = (struct fdt_header *)fdt;

  // Only process FDT that we understand
  if (bswap(header->magic) != FDT_MAGIC ||
      bswap(header->last_comp_version) > FDT_VERSION) return;

  const char *strings = (const char *)(fdt + bswap(header->off_dt_strings));
  uint32_t *lex = (uint32_t *)(fdt + bswap(header->off_dt_struct));

  fdt_scan_helper(lex, strings, 0, cb);
}

uint32_t fdt_size(uintptr_t fdt)
{
  struct fdt_header *header = (struct fdt_header *)fdt;

  // Only process FDT that we understand
  if (bswap(header->magic) != FDT_MAGIC ||
      bswap(header->last_comp_version) > FDT_VERSION) return 0;
  return bswap(header->totalsize);
}

const uint32_t *fdt_get_address(const struct fdt_scan_node *node, const uint32_t *value, uint64_t *result)
{
  *result = 0;
  for (int cells = node->address_cells; cells > 0; --cells)
    *result = (*result << 32) + bswap(*value++);
  return value;
}

const uint32_t *fdt_get_size(const struct fdt_scan_node *node, const uint32_t *value, uint64_t *result)
{
  *result = 0;
  for (int cells = node->size_cells; cells > 0; --cells)
    *result = (*result << 32) + bswap(*value++);
  return value;
}

uint32_t fdt_get_value(const struct fdt_scan_prop *prop, uint32_t index)
{
  return bswap(prop->value[index]);
}

int fdt_string_list_index(const struct fdt_scan_prop *prop, const char *str)
{
  const char *list = (const char *)prop->value;
  const char *end = list + prop->len;
  int index = 0;
  while (end - list > 0) {
    if (!strcmp(list, str)) return index;
    ++index;
    list += strlen(list) + 1;
  }
  return -1;
}

//////////////////////////////////////////// MEMORY SCAN /////////////////////////////////////////

struct mem_scan {
  int memory;
  const uint32_t *reg_value;
  int reg_len;
};

static void mem_open(const struct fdt_scan_node *node, void *extra)
{
  struct mem_scan *scan = (struct mem_scan *)extra;
  memset(scan, 0, sizeof(*scan));
}

static void mem_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct mem_scan *scan = (struct mem_scan *)extra;
  if (!strcmp(prop->name, "device_type") && !strcmp((const char*)prop->value, "memory")) {
    scan->memory = 1;
  } else if (!strcmp(prop->name, "reg")) {
    scan->reg_value = prop->value;
    scan->reg_len = prop->len;
  }
}

static void mem_done(const struct fdt_scan_node *node, void *extra)
{
  struct mem_scan *scan = (struct mem_scan *)extra;
  const uint32_t *value = scan->reg_value;
  const uint32_t *end = value + scan->reg_len/4;
  uintptr_t self = (uintptr_t)mem_done;

  if (!scan->memory) return;
  assert (scan->reg_value && scan->reg_len % 4 == 0);

  while (end - value > 0) {
    uint64_t base, size;
    value = fdt_get_address(node->parent, value, &base);
    value = fdt_get_size   (node->parent, value, &size);
    if (base <= self && self <= base + size) {
      //NOTE: proxykernel and tagging code uses these variables
      mem_size = size;
      mem_base = base;
      mem_size_final = mem_size; //needed for pk-mmap (in case we dont run tag_init for some reason)
    }
  }
  assert (end == value);
}

/*
uint8_t isTaggingActive()
{
    uint64_t tag_mode = CSRR(CSR_U_TAG_MODE);
    if (tag_mode != MTAG0)
        return 1;
    else
        return 0;
}
*/

void query_mem(uintptr_t fdt)
{
  struct fdt_cb cb;
  struct mem_scan scan;

  memset(&cb, 0, sizeof(cb));
  cb.open = mem_open;
  cb.prop = mem_prop;
  cb.done = mem_done;
  cb.extra = &scan;

  mem_size = 0;
  fdt_scan(fdt, &cb);
  assert (mem_size > 0);
}
////////////////////////////////////////////////////////////////////////////////


struct tagged_mem_scan {
  int memory;
  const uint32_t *reg_value;
  int reg_len;
  size_t count;
};

static void tagged_memory_open(const struct fdt_scan_node *node, void *extra)
{
  struct tagged_mem_scan *scan = (struct tagged_mem_scan *)extra;
  size_t count = scan->count;
  memset(scan, 0, sizeof(*scan));
  scan->count = count;
}

static void tagged_memory_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct tagged_mem_scan *scan = (struct tagged_mem_scan *)extra;
  if (!strcmp(prop->name, "device_type") && !strcmp((const char*)prop->value, "memory")) {
    scan->memory = 1;
    scan->count++;
  } else if (!strcmp(prop->name, "reg")) {
    scan->reg_value = prop->value;
    scan->reg_len = prop->len;
  }
}

static void tagged_memory_done(const struct fdt_scan_node *node, void *extra)
{
  struct tagged_mem_scan *scan = (struct tagged_mem_scan *)extra;
  const uint32_t *value = scan->reg_value;
  const uint32_t *end = value + scan->reg_len/4;
  uintptr_t self = (uintptr_t)mem_done;

  if (!scan->memory) return;
  assert (scan->reg_value && scan->reg_len % 4 == 0);
  print_debug("scan->reg_len =       0x%x\n", scan->reg_len);

  assert (scan->count == 1); //TODO currently we dont suppoert more than 1 memory region

  uint64_t base = 0;
  uint64_t size = 0;
  while (end - value > 0) {
    value = fdt_get_address(node->parent, value, &base);
    uint32_t * start_addr_of_size = (uint32_t *)value;
    value = fdt_get_size(node->parent, value, &size);
    print_debug("node->size_cells =    0x%x\n", node->parent->size_cells);
    print_debug("node->address_cells = 0x%x\n", node->parent->address_cells);
    //assert(node->parent->size_cells == 0); //TODO if this fails: need to do the opposite of fdt_get_size

    uintptr_t self = (uintptr_t)tagged_memory_done;
    if (base <= self && self <= base + size) {
      //uint64_t reserved_size_for_tagstore = get_max_tagstorage_size(size);
      uint64_t reserved_size_for_tagstore = get_max_tagstorage_size(size + base); // tagging entire address space from 0 to ram-end
      uint64_t new_size = size - reserved_size_for_tagstore;
      mem_size_final = new_size; // used by pk-mmap

      print_debug("base =                0x%lx\n", base);
      print_always("size =                0x%lx (%ld MB)\n", size, size / 1024 / 1024);
      print_always("new_size =            0x%lx (%ld MB)\n", new_size, new_size / 1024 / 1024);
      print_always("reserved for tagstore 0x%lx (%ld MB)\n", reserved_size_for_tagstore, reserved_size_for_tagstore / 1024 / 1024);

      //*(uint32_t *)value = bswap(new_size); //this might work for 32-bit memory sizes. but it's wrong.

      uint32_t *tmp_address = (uint32_t *)start_addr_of_size;
      uint64_t tmp_size = new_size;
      assert(node->parent->size_cells >= 1 && node->parent->size_cells <= 2); // "value" must be a 32 or 64bit integer (1 or 2 cells with size 4-bytes)
      for (int cells = node->parent->size_cells; cells > 0; --cells){
        uint32_t tmp = new_size >> (32 * (cells-1));
        tmp_size >>= 32;
        tmp = bswap(tmp);
        print_debug("writing 0x%x (bswap = 0x%x) to 0x%x. Previous value = 0x%x (bswap = 0x%x)\n", tmp, bswap(tmp), tmp_address, *tmp_address, bswap(*tmp_address));
        *tmp_address = tmp;
        tmp_address++;
      }

      //read value again to make sure it is correct
      uint64_t tmp2 = 0;
      fdt_get_size(node->parent, start_addr_of_size, &tmp2);
      assert(tmp2 == new_size);
    }
  }
}

void filter_tagged_memory(uintptr_t fdt){
  //print_debug("filter_tagged_memory  0x%x\n", fdt);
  #if defined(DEBUG_FDT_TREE) && DEBUG_FDT_TREE == 1
    fdt_print(fdt);
  #endif

  struct fdt_cb cb;
  struct tagged_mem_scan scan;
  memset(&cb, 0, sizeof(cb));
  memset(&scan, 0, sizeof(scan));
  cb.open = tagged_memory_open;
  cb.prop = tagged_memory_prop;
  cb.done = tagged_memory_done;
  cb.extra = &scan;
  fdt_scan(fdt, &cb);

  #if defined(DEBUG_FDT_TREE) && DEBUG_FDT_TREE == 1
    print_debug("----------------------\n");
    fdt_print(fdt);
    print_debug("----------------------\n");
  #endif
}


////////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////// HART SCAN //////////////////////////////////////////

static uint32_t hart_phandles[MAX_HARTS];
uint64_t hart_mask;

struct hart_scan {
  const struct fdt_scan_node *cpu;
  int hart;
  const struct fdt_scan_node *controller;
  int cells;
  uint32_t phandle;
};

static void hart_open(const struct fdt_scan_node *node, void *extra)
{
  struct hart_scan *scan = (struct hart_scan *)extra;
  if (!scan->cpu) {
    scan->hart = -1;
  }
  if (!scan->controller) {
    scan->cells = 0;
    scan->phandle = 0;
  }
}

static void hart_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct hart_scan *scan = (struct hart_scan *)extra;
  if (!strcmp(prop->name, "device_type") && !strcmp((const char*)prop->value, "cpu")) {
    assert (!scan->cpu);
    scan->cpu = prop->node;
  } else if (!strcmp(prop->name, "interrupt-controller")) {
    assert (!scan->controller);
    scan->controller = prop->node;
  } else if (!strcmp(prop->name, "#interrupt-cells")) {
    scan->cells = bswap(prop->value[0]);
  } else if (!strcmp(prop->name, "phandle")) {
    scan->phandle = bswap(prop->value[0]);
  } else if (!strcmp(prop->name, "reg")) {
    uint64_t reg;
    fdt_get_address(prop->node->parent, prop->value, &reg);
    scan->hart = reg;
  }
}

static void hart_done(const struct fdt_scan_node *node, void *extra)
{
  struct hart_scan *scan = (struct hart_scan *)extra;

  if (scan->cpu == node) {
    assert (scan->hart >= 0);
  }

  if (scan->controller == node && scan->cpu) {
    assert (scan->phandle > 0);
    assert (scan->cells == 1);

    if (scan->hart < MAX_HARTS) {
      hart_phandles[scan->hart] = scan->phandle;
      hart_mask |= 1 << scan->hart;
      hls_init(scan->hart);
    }
  }
}

static int hart_close(const struct fdt_scan_node *node, void *extra)
{
  struct hart_scan *scan = (struct hart_scan *)extra;
  if (scan->cpu == node) scan->cpu = 0;
  if (scan->controller == node) scan->controller = 0;
  return 0;
}

void query_harts(uintptr_t fdt)
{
  struct fdt_cb cb;
  struct hart_scan scan;

  memset(&cb, 0, sizeof(cb));
  memset(&scan, 0, sizeof(scan));
  cb.open = hart_open;
  cb.prop = hart_prop;
  cb.done = hart_done;
  cb.close= hart_close;
  cb.extra = &scan;

  fdt_scan(fdt, &cb);

  // The current hart should have been detected
  assert ((hart_mask >> read_csr(mhartid)) != 0);
}

///////////////////////////////////////////// CLINT SCAN /////////////////////////////////////////

struct clint_scan
{
  int compat;
  uint64_t reg;
  const uint32_t *int_value;
  int int_len;
  int done;
};

static void clint_open(const struct fdt_scan_node *node, void *extra)
{
  struct clint_scan *scan = (struct clint_scan *)extra;
  scan->compat = 0;
  scan->reg = 0;
  scan->int_value = 0;
}

static void clint_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct clint_scan *scan = (struct clint_scan *)extra;
  if (!strcmp(prop->name, "compatible") && fdt_string_list_index(prop, "riscv,clint0") >= 0) {
    scan->compat = 1;
  } else if (!strcmp(prop->name, "reg")) {
    fdt_get_address(prop->node->parent, prop->value, &scan->reg);
  } else if (!strcmp(prop->name, "interrupts-extended")) {
    scan->int_value = prop->value;
    scan->int_len = prop->len;
  }
}

static void clint_done(const struct fdt_scan_node *node, void *extra)
{
  struct clint_scan *scan = (struct clint_scan *)extra;
  const uint32_t *value = scan->int_value;
  const uint32_t *end = value + scan->int_len/4;

  if (!scan->compat) return;
  assert (scan->reg != 0);
  assert (scan->int_value && scan->int_len % 16 == 0);
  assert (!scan->done); // only one clint

  scan->done = 1;
  mtime = (void*)((uintptr_t)scan->reg + 0xbff8);

  for (int index = 0; end - value > 0; ++index) {
    uint32_t phandle = bswap(value[0]);
    int hart;
    for (hart = 0; hart < MAX_HARTS; ++hart)
      if (hart_phandles[hart] == phandle)
        break;
    if (hart < MAX_HARTS) {
      hls_t *hls = OTHER_HLS(hart);
      hls->ipi = (void*)((uintptr_t)scan->reg + index * 4);
      hls->timecmp = (void*)((uintptr_t)scan->reg + 0x4000 + (index * 8));
    }
    value += 4;
  }
}

void query_clint(uintptr_t fdt)
{
  struct fdt_cb cb;
  struct clint_scan scan;

  memset(&cb, 0, sizeof(cb));
  cb.open = clint_open;
  cb.prop = clint_prop;
  cb.done = clint_done;
  cb.extra = &scan;

  scan.done = 0;
  fdt_scan(fdt, &cb);
  assert (scan.done);
}

///////////////////////////////////////////// PLIC SCAN /////////////////////////////////////////

struct plic_scan
{
  int compat;
  uint64_t reg;
  uint32_t *int_value;
  int int_len;
  int done;
  int ndev;
};

static void plic_open(const struct fdt_scan_node *node, void *extra)
{
  struct plic_scan *scan = (struct plic_scan *)extra;
  scan->compat = 0;
  scan->reg = 0;
  scan->int_value = 0;
}

static void plic_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct plic_scan *scan = (struct plic_scan *)extra;
  if (!strcmp(prop->name, "compatible") && fdt_string_list_index(prop, "riscv,plic0") >= 0) {
    scan->compat = 1;
  } else if (!strcmp(prop->name, "reg")) {
    fdt_get_address(prop->node->parent, prop->value, &scan->reg);
  } else if (!strcmp(prop->name, "interrupts-extended")) {
    scan->int_value = prop->value;
    scan->int_len = prop->len;
  } else if (!strcmp(prop->name, "riscv,ndev")) {
    scan->ndev = bswap(prop->value[0]);
  }
}

#define HART_BASE	0x200000
#define HART_SIZE	0x1000
#define ENABLE_BASE	0x2000
#define ENABLE_SIZE	0x80

static void plic_done(const struct fdt_scan_node *node, void *extra)
{
  struct plic_scan *scan = (struct plic_scan *)extra;
  const uint32_t *value = scan->int_value;
  const uint32_t *end = value + scan->int_len/4;

  if (!scan->compat) return;
  assert (scan->reg != 0);
  assert (scan->int_value && scan->int_len % 8 == 0);
  assert (scan->ndev >= 0 && scan->ndev < 1024);
  assert (!scan->done); // only one plic

  scan->done = 1;
  plic_priorities = (uint32_t*)(uintptr_t)scan->reg;
  plic_ndevs = scan->ndev;

  for (int index = 0; end - value > 0; ++index) {
    uint32_t phandle = bswap(value[0]);
    uint32_t cpu_int = bswap(value[1]);
    int hart;
    for (hart = 0; hart < MAX_HARTS; ++hart)
      if (hart_phandles[hart] == phandle)
        break;
    if (hart < MAX_HARTS) {
      hls_t *hls = OTHER_HLS(hart);
      if (cpu_int == IRQ_M_EXT) {
        hls->plic_m_ie     = (uint32_t*)((uintptr_t)scan->reg + ENABLE_BASE + ENABLE_SIZE * index);
        hls->plic_m_thresh = (uint32_t*) ((uintptr_t)scan->reg + HART_BASE   + HART_SIZE   * index);
      } else if (cpu_int == IRQ_S_EXT) {
        hls->plic_s_ie     = (uint32_t*)((uintptr_t)scan->reg + ENABLE_BASE + ENABLE_SIZE * index);
        hls->plic_s_thresh = (uint32_t*) ((uintptr_t)scan->reg + HART_BASE   + HART_SIZE   * index);
      } else {
        printm("PLIC wired hart %d to wrong interrupt %d", hart, cpu_int);
      }
    }
    value += 2;
  }
#if 0
  printm("PLIC: prio %x devs %d\r\n", (uint32_t)(uintptr_t)plic_priorities, plic_ndevs);
  for (int i = 0; i < MAX_HARTS; ++i) {
    hls_t *hls = OTHER_HLS(i);
    printm("CPU %d: %x %x %x %x\r\n", i, (uint32_t)(uintptr_t)hls->plic_m_ie, (uint32_t)(uintptr_t)hls->plic_m_thresh, (uint32_t)(uintptr_t)hls->plic_s_ie, (uint32_t)(uintptr_t)hls->plic_s_thresh);
  }
#endif
}

void query_plic(uintptr_t fdt)
{
  struct fdt_cb cb;
  struct plic_scan scan;

  memset(&cb, 0, sizeof(cb));
  cb.open = plic_open;
  cb.prop = plic_prop;
  cb.done = plic_done;
  cb.extra = &scan;

  scan.done = 0;
  fdt_scan(fdt, &cb);
}

static void plic_redact(const struct fdt_scan_node *node, void *extra)
{
  struct plic_scan *scan = (struct plic_scan *)extra;
  uint32_t *value = scan->int_value;
  uint32_t *end = value + scan->int_len/4;

  if (!scan->compat) return;
  scan->done = 1;

  while (end - value > 0) {
    if (bswap(value[1]) == IRQ_M_EXT) value[1] = bswap(-1);
    value += 2;
  }
}

void filter_plic(uintptr_t fdt)
{
  struct fdt_cb cb;
  struct plic_scan scan;

  memset(&cb, 0, sizeof(cb));
  cb.open = plic_open;
  cb.prop = plic_prop;
  cb.done = plic_redact;
  cb.extra = &scan;

  scan.done = 0;
  fdt_scan(fdt, &cb);
}

//////////////////////////////////////////// COMPAT SCAN ////////////////////////////////////////

struct compat_scan
{
  const char *compat;
  int depth;
  int kill;
};

static void compat_open(const struct fdt_scan_node *node, void *extra)
{
  struct compat_scan *scan = (struct compat_scan *)extra;
  ++scan->depth;
}

static void compat_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct compat_scan *scan = (struct compat_scan *)extra;
  if (!strcmp(prop->name, "compatible") && fdt_string_list_index(prop, scan->compat) >= 0)
    if (scan->depth < scan->kill)
      scan->kill = scan->depth;
}

static int compat_close(const struct fdt_scan_node *node, void *extra)
{
  struct compat_scan *scan = (struct compat_scan *)extra;
  if (scan->kill == scan->depth--) {
    scan->kill = 999;
    return -1;
  } else {
    return 0;
  }
}

void filter_compat(uintptr_t fdt, const char *compat)
{
  struct fdt_cb cb;
  struct compat_scan scan;

  memset(&cb, 0, sizeof(cb));
  cb.open = compat_open;
  cb.prop = compat_prop;
  cb.close = compat_close;
  cb.extra = &scan;

  scan.compat = compat;
  scan.depth = 0;
  scan.kill = 999;
  fdt_scan(fdt, &cb);
}

//////////////////////////////////////////// CHOSEN SCAN ////////////////////////////////////////

struct chosen_scan {
  const struct fdt_scan_node *chosen;
  void* kernel_start;
  void* kernel_end;
};

static void chosen_open(const struct fdt_scan_node *node, void *extra)
{
  struct chosen_scan *scan = (struct chosen_scan *)extra;
  if (!strcmp(node->name, "chosen")) {
    scan->chosen = node;
  }
}

static int chosen_close(const struct fdt_scan_node *node, void *extra)
{
  struct chosen_scan *scan = (struct chosen_scan *)extra;
  if (scan->chosen && scan->chosen == node) {
    scan->chosen = NULL;
  }
  return 0;
}

static void chosen_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct chosen_scan *scan = (struct chosen_scan *)extra;
  uint64_t val;
  if (!scan->chosen) return;
  if (!strcmp(prop->name, "riscv,kernel-start")) {
    fdt_get_address(prop->node->parent, prop->value, &val);
    scan->kernel_start = (void*)(uintptr_t)val;
  } else if (!strcmp(prop->name, "riscv,kernel-end")) {
    fdt_get_address(prop->node->parent, prop->value, &val);
    scan->kernel_end = (void*)(uintptr_t)val;
  }
}

void query_chosen(uintptr_t fdt)
{
  struct fdt_cb cb;
  struct chosen_scan chosen;

  memset(&cb, 0, sizeof(cb));
  cb.open = chosen_open;
  cb.close = chosen_close;
  cb.prop = chosen_prop;

  memset(&chosen, 0, sizeof(chosen));
  cb.extra = &chosen;

  fdt_scan(fdt, &cb);
  kernel_start = chosen.kernel_start;
  kernel_end = chosen.kernel_end;
}

//////////////////////////////////////////// HART FILTER ////////////////////////////////////////

struct hart_filter {
  int compat;
  int hart;
  char *status;
  char *mmu_type;
  long *disabled_hart_mask;
};

static void hart_filter_open(const struct fdt_scan_node *node, void *extra)
{
  struct hart_filter *filter = (struct hart_filter *)extra;
  filter->status = NULL;
  filter->mmu_type = NULL;
  filter->compat = 0;
  filter->hart = -1;
}

static void hart_filter_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct hart_filter *filter = (struct hart_filter *)extra;
  if (!strcmp(prop->name, "device_type") && !strcmp((const char*)prop->value, "cpu")) {
    filter->compat = 1;
  } else if (!strcmp(prop->name, "reg")) {
    uint64_t reg;
    fdt_get_address(prop->node->parent, prop->value, &reg);
    filter->hart = reg;
  } else if (!strcmp(prop->name, "status")) {
    filter->status = (char*)prop->value;
  } else if (!strcmp(prop->name, "mmu-type")) {
    filter->mmu_type = (char*)prop->value;
  }
}

static bool hart_filter_mask(const struct hart_filter *filter)
{
  if (filter->mmu_type == NULL) return true;
  if (strcmp(filter->status, "okay")) return true;
#if __riscv_xlen == 32
  if (!strcmp(filter->mmu_type, "riscv,sv32")) return false;
#else
  if (!strcmp(filter->mmu_type, "riscv,sv39")) return false;
  if (!strcmp(filter->mmu_type, "riscv,sv48")) return false;
#endif
  printm("hart_filter_mask saw unknown hart type: status=\"%s\", mmu_type=\"%s\"\n",
         filter->status, filter->mmu_type);
  return true;
}

static void hart_filter_done(const struct fdt_scan_node *node, void *extra)
{
  struct hart_filter *filter = (struct hart_filter *)extra;

  if (!filter->compat) return;
  assert (filter->status);
  assert (filter->hart >= 0);

  if (hart_filter_mask(filter)) {
    strcpy(filter->status, "masked");
    uint32_t *len = (uint32_t*)filter->status;
    len[-2] = bswap(strlen("masked")+1);
    *filter->disabled_hart_mask |= (1 << filter->hart);
  }
}

void filter_harts(uintptr_t fdt, long *disabled_hart_mask)
{
  struct fdt_cb cb;
  struct hart_filter filter;

  memset(&cb, 0, sizeof(cb));
  cb.open = hart_filter_open;
  cb.prop = hart_filter_prop;
  cb.done = hart_filter_done;
  cb.extra = &filter;

  filter.disabled_hart_mask = disabled_hart_mask;
  *disabled_hart_mask = 0;
  fdt_scan(fdt, &cb);
}

//////////////////////////////////////////// PRINT //////////////////////////////////////////////

//#ifdef PK_PRINT_DEVICE_TREE
#if 1
#define FDT_PRINT_MAX_DEPTH 32

struct fdt_print_info {
  int depth;
  const struct fdt_scan_node *stack[FDT_PRINT_MAX_DEPTH];
};

void fdt_print_printm(struct fdt_print_info *info, const char *format, ...)
{
  va_list vl;

  for (int i = 0; i < info->depth; ++i)
    printm("  ");

  va_start(vl, format);
  vprintm(format, vl);
  va_end(vl);
}

static void fdt_print_open(const struct fdt_scan_node *node, void *extra)
{
  struct fdt_print_info *info = (struct fdt_print_info *)extra;

  while (node->parent != NULL && info->stack[info->depth-1] != node->parent) {
    info->depth--;
    fdt_print_printm(info, "}\r\n");
  }

  fdt_print_printm(info, "%s {\r\n", node->name);
  info->stack[info->depth] = node;
  info->depth++;
}

static void fdt_print_prop(const struct fdt_scan_prop *prop, void *extra)
{
  struct fdt_print_info *info = (struct fdt_print_info *)extra;
  int asstring = 1;
  char *char_data = (char *)(prop->value);

  fdt_print_printm(info, "%s", prop->name);

  if (prop->len == 0) {
    printm(";\r\n");
    return;
  } else {
    printm(" = ");
  }

  /* It appears that dtc uses a hueristic to detect strings so I'm using a
   * similar one here. */
  for (int i = 0; i < prop->len; ++i) {
    if (!isstring(char_data[i]))
      asstring = 0;
    if (i > 0 && char_data[i] == '\0' && char_data[i-1] == '\0')
      asstring = 0;
  }

  if (asstring) {
    for (size_t i = 0; i < prop->len; i += strlen(char_data + i) + 1) {
      if (i != 0)
        printm(", ");
      printm("\"%s\"", char_data + i);
    }
  } else {
    printm("<");
    for (size_t i = 0; i < prop->len/4; ++i) {
      if (i != 0)
        printm(" ");
      printm("0x%08x", bswap(prop->value[i]));
    }
    printm(">");
  }

  printm(";\r\n");
}

static void fdt_print_done(const struct fdt_scan_node *node, void *extra)
{
  struct fdt_print_info *info = (struct fdt_print_info *)extra;
}

static int fdt_print_close(const struct fdt_scan_node *node, void *extra)
{
  struct fdt_print_info *info = (struct fdt_print_info *)extra;
  return 0;
}

void fdt_print(uintptr_t fdt)
{
  struct fdt_print_info info;
  struct fdt_cb cb;

  info.depth = 0;

  memset(&cb, 0, sizeof(cb));
  cb.open = fdt_print_open;
  cb.prop = fdt_print_prop;
  cb.done = fdt_print_done;
  cb.close = fdt_print_close;
  cb.extra = &info;

  fdt_scan(fdt, &cb);

  while (info.depth > 0) {
    info.depth--;
    fdt_print_printm(&info, "}\r\n");
  }
}
#endif
