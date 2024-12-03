#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/synch.h"
#include "threads/palloc.h"
#include <hash.h>
#include "lib/kernel/hash.h"
typedef int fid_t;

enum frame_status
  {
    FRAME_UNUSED,
    FRAME_USED,
    FRAME_PINNED
  };

struct frame_table_entry
  {
    fid_t fid;
    enum frame_status status;
    void *kpage;
    struct hash_elem kpage_elem; /* Hash table element. */
    struct hash_elem fid_elem;
  };

void frame_init (void);
void *frame_get_page (enum palloc_flags);
void frame_free_page (void *);
static fid_t allocate_fid(void);
struct frame_table_entry* search_by_fid(fid_t);
struct frame_table_entry* search_by_page(void *);
#endif /* vm/frame.h */
