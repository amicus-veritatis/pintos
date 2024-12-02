#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"

#include <hash.h>
#include "lib/kernel/hash.h"

#define O_DIRTY 0x04

#define O_PG_MASK 0x03
#define O_PG_SWAP 0x03
#define O_PG_ALL_ZERO 0x02
#define O_PG_FS 0x01
#define O_PG_FRAME 0x00

struct supp_page_table_entry {
  void *upage;
  uint8_t flags;
  struct hash_elem elem;
};

unsigned supp_hash (const struct hash_elem *, void * UNUSED);
bool supp_less (const struct hash_elem *, const struct hash_elem *, void * UNUSED);

#endif
