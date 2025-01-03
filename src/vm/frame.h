#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/synch.h"
#include "threads/palloc.h"
#include <hash.h>
#include "lib/kernel/hash.h"
#include <list.h>
#include "lib/kernel/list.h"
typedef int fid_t;

enum frame_status
  {
    FRAME_USED,
    FRAME_PINNED
  };

struct frame_table_entry
  {
    fid_t fid;
    enum frame_status status;
    void *kpage;
    void *upage;
    struct hash_elem kpage_elem; /* Hash table element. */
    struct hash_elem fid_elem;
    struct list_elem list_elem;
    struct thread *t;
    uint32_t *pd;
  };

void frame_init (void);
void *frame_get_page (enum palloc_flags, void *);
void frame_free_page_with_lock (void *);
void frame_free_page (void *);
static fid_t allocate_fid(void);
struct frame_table_entry* search_by_fid(fid_t);
struct frame_table_entry* search_by_page(void *);
void set_pinned (void *, bool);
#endif /* vm/frame.h */
