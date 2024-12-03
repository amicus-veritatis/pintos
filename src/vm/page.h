#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "filesys/off_t.h"
#include "threads/thread.h"
#include <hash.h>
#include "lib/kernel/hash.h"

#define O_DIRTY 0x08
#define O_WRITABLE 0x04

#define O_NON_PG_MASK 0x0C
#define O_PG_MASK 0x03
#define O_PG_SWAP 0x03
#define O_PG_ALL_ZERO 0x02
#define O_PG_FS 0x01
#define O_PG_MEM 0x00

struct supp_page_table_entry {
  void *upage;
  void *kpage;
  struct file *file;
  off_t ofs;
  uint32_t read_bytes;
  uint32_t zero_bytes;
  uint8_t flags;
  struct hash_elem elem;
};

unsigned supp_hash (const struct hash_elem *, void * UNUSED);
bool supp_less (const struct hash_elem *, const struct hash_elem *, void * UNUSED);
struct supp_page_table_entry* search_by_addr(struct thread *, void *);
void grow_stack (struct thread *, void *);
void supp_destroy (struct hash_elem *, void * UNUSED);

#endif
