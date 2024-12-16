#include <hash.h>
#include <list.h>

#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <lib/debug.h>
#define JUNK (0xCCCCCCCC)
struct lock frame_lock;
struct hash frame_hash_map_by_kpage;
struct hash frame_hash_map_by_fid;
struct list frame_list;
struct list_elem *clock;
struct lock fid_lock;

static unsigned
frame_kpage_hash(const struct hash_elem *f_, void *aux UNUSED)
{
  const struct frame_table_entry *frame = hash_entry(f_, struct frame_table_entry, kpage_elem);
  return hash_bytes(&(frame->kpage), sizeof(frame->kpage));
}

static bool
frame_kpage_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
  const struct frame_table_entry *a = hash_entry (a_, struct frame_table_entry, kpage_elem);
  const struct frame_table_entry *b = hash_entry (b_, struct frame_table_entry, kpage_elem);
  return a->kpage < b->kpage;
}

static unsigned
frame_fid_hash(const struct hash_elem *f_, void *aux UNUSED)
{
  const struct frame_table_entry *frame = hash_entry(f_, struct frame_table_entry, fid_elem);
  return hash_bytes(&(frame->fid), sizeof(frame->fid));
}

static bool
frame_fid_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
  const struct frame_table_entry *a = hash_entry (a_, struct frame_table_entry, fid_elem);
  const struct frame_table_entry *b = hash_entry (b_, struct frame_table_entry, fid_elem);
  return a->fid < b->fid;
}

void
frame_init()
{
  lock_init(&frame_lock);
  hash_init(&frame_hash_map_by_kpage, frame_kpage_hash, frame_kpage_less, NULL);
  hash_init(&frame_hash_map_by_fid, frame_fid_hash, frame_fid_less, NULL);
  list_init(&frame_list);
  lock_init(&fid_lock);
  clock = NULL;
}

static fid_t
allocate_fid()
{
  static fid_t next_fid = 1;
  fid_t fid;
  
  lock_acquire(&fid_lock);
  fid = next_fid++;
  lock_release(&fid_lock);
  
  return fid;
}

struct frame_table_entry*
search_by_page(void *page)
{
  struct frame_table_entry tmp;
  tmp.kpage = page;
  struct hash_elem *tmp_elem = hash_find(&frame_hash_map_by_kpage, &(tmp.kpage_elem));
  if (tmp_elem == NULL) {
    return NULL;
  }
  return hash_entry(tmp_elem, struct frame_table_entry, kpage_elem);
}

struct frame_table_entry*
search_by_fid(fid_t fid)
{
  struct frame_table_entry tmp;
  tmp.fid = fid;
  struct hash_elem *tmp_elem = hash_find(&frame_hash_map_by_fid, &(tmp.fid_elem));
  if (tmp_elem == NULL) {
    return NULL;
  }
  return hash_entry(tmp_elem, struct frame_table_entry, fid_elem);
}
struct frame_table_entry* clock_next (void);
static inline struct frame_table_entry* frame_evicted (void);
void evict_cleanup(struct frame_table_entry *, struct supp_page_table_entry *);

struct frame_table_entry*
clock_next (void)
{
  ASSERT(!list_empty(&frame_list));
  if (clock == NULL || list_next(clock) == list_end(&frame_list) || clock == list_end(&frame_list)) {
    clock = list_begin(&frame_list);
  } else {
    clock = list_next(clock);
  }
  struct frame_table_entry *ret = list_entry(clock, struct frame_table_entry, list_elem);
  ASSERT (ret != NULL);
  return ret;
}


static inline struct frame_table_entry*
frame_evicted ()
{
  struct frame_table_entry *f = clock_next();
  uint32_t *pd = NULL;
  void *upage = NULL;
  for (;;f=clock_next()) {
    if (f->status == FRAME_PINNED) {
      continue;
    }
    pd = f->t->pagedir;
    upage = f->upage;
    ASSERT(f->t != NULL);
    // printf("current frame: %p, ", f);
    // printf("pagedir_is_accessed(%p, %p) ", pd, upage);
    if (pd == JUNK || pd == NULL || pd > PHYS_BASE) {
      return f;
    }
    if (pagedir_is_accessed(pd, upage) == true) {
      pagedir_set_accessed(pd, upage, false);
      continue;
    }
    return f;
  }
  NOT_REACHED();
}

/* This function actually allocates frame_table_entry, not page,
 * but because this function intends to replace palloc_get_page,
 * we name this frame_get_page.
 */
void*
frame_get_page(enum palloc_flags flags, void *upage)
{
  lock_acquire(&frame_lock);
  ASSERT (upage != NULL);
  void *page = palloc_get_page(PAL_USER | flags);
  if (page == NULL) {
    // printf("eviction 시작!\n");
    struct frame_table_entry *evicted = frame_evicted();
    struct supp_page_table_entry *s = search_by_addr(evicted->t, evicted->upage);
    evict_cleanup(evicted, s);
    page = palloc_get_page(PAL_USER | flags);
    ASSERT (page != NULL);
  }

  struct frame_table_entry *frame = malloc(sizeof(struct frame_table_entry));
  ASSERT (frame != NULL);
  struct thread *t = thread_current();
  frame->t = t;
  frame->pd = t->pagedir;
  frame->fid = allocate_fid();
  frame->kpage = page;
  frame->upage = upage;
  frame->status = FRAME_USED;
  ASSERT(frame->upage == upage);
  hash_insert(&frame_hash_map_by_kpage, &(frame->kpage_elem));
  hash_insert(&frame_hash_map_by_fid, &(frame->fid_elem));
  list_push_back(&frame_list, &(frame->list_elem));
  lock_release(&frame_lock);

  /* This function is substitute of palloc_get_page, so should return the same thing. */
  return page;
}

/* This only should be called in frame_get_page
 * otherwise lock will be cursed
 */
void
evict_cleanup(struct frame_table_entry *evicted, struct supp_page_table_entry *s)
{
  ASSERT(evicted->kpage != NULL);
	if (pagedir_is_dirty(evicted->t->pagedir, evicted->upage)) {
    s->flags |= O_DIRTY;
  };

  pagedir_clear_page(evicted->t->pagedir, evicted->upage);
  s->swap_idx = swap_out(evicted->kpage);
  s->flags = (s->flags & ~O_PG_MASK) | O_PG_SWAP;
  s->kpage = NULL;
  palloc_free_page(evicted->kpage);
  hash_delete(&frame_hash_map_by_kpage, &evicted->kpage_elem);
  hash_delete(&frame_hash_map_by_fid, &evicted->fid_elem);
  list_remove(&evicted->list_elem);

  free(evicted);
}
/* The name is blatantly untrue.
 * but it would be nice if it uses same name,
 * and nobody except me will manage this code anyway.
 */
void
frame_free_page(void *page)
{
  /* Do not trust anything. */
  if (pg_ofs(page)) {
    PANIC ("Pintos Manual Section 4.1.2.2: frames must be page-size and page-aligned.");
  }
  struct frame_table_entry *frame = search_by_page(page);
  if (frame == NULL) {
    PANIC ("Such page does not exist!");
  }
  pagedir_clear_page(frame->t->pagedir, frame->upage);
  palloc_free_page(page);
  lock_acquire(&frame_lock);
  hash_delete(&frame_hash_map_by_kpage, &frame->kpage_elem);
  hash_delete(&frame_hash_map_by_fid, &frame->fid_elem);
  list_remove(&frame->list_elem);

  free(frame);
  lock_release(&frame_lock);
}

void
set_pinned (void *kpage, bool pinned)
{
  lock_acquire(&frame_lock);
  struct frame_table_entry *f = search_by_page(kpage);
  if (pinned) {
    f->status = FRAME_PINNED;
  } else {
    f->status = FRAME_USED;
  }
  lock_release(&frame_lock);
}
