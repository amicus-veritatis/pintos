#include <hash.h>

#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"

struct lock frame_lock;
struct hash frame_hash_map_by_vtop;
struct hash frame_hash_map_by_fid;
struct list frame_list;
struct lock fid_lock;

unsigned
frame_vtop_hash(const struct hash_elem *f_, void *aux UNUSED)
{
  const struct frame_table_entry *frame = hash_entry(f_, struct frame_table_entry, vtop_elem);
  return hash_bytes(&(frame->vtop), sizeof(frame->vtop));
}

bool
frame_vtop_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
  const struct frame_table_entry *a = hash_entry (a_, struct frame_table_entry, vtop_elem);
  const struct frame_table_entry *b = hash_entry (b_, struct frame_table_entry, vtop_elem);
  return a->vtop < b->vtop;
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
  hash_init(&frame_hash_map_by_vtop, frame_vtop_hash, frame_vtop_less, NULL);
  hash_init(&frame_hash_map_by_fid, frame_fid_hash, frame_fid_less, NULL);
  lock_init(&fid_lock);
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
  tmp.vtop = vtop(page);
  struct hash_elem *tmp_elem = hash_find(&frame_hash_map_by_vtop, &(tmp.vtop_elem));
  if (tmp_elem == NULL) {
    return NULL;
  }
  return hash_entry(tmp_elem, struct frame_table_entry, vtop_elem);
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


/* This function actually allocates frame_table_entry, not page,
 * but because this function intends to replace palloc_get_page,
 * we name this frame_get_page.
 */
void*
frame_get_page(enum palloc_flags flags)
{
  void *page = palloc_get_page(PAL_USER | flags);
  if (page == NULL) {
    return NULL;
  }

  struct frame_table_entry *frame = palloc_get_page(0);
  if (frame == NULL) {
    palloc_free_page(page);
    return NULL;
  }

  frame->fid = allocate_fid();
  frame->upage = page;
  frame->vtop = (void *) vtop(page);
  frame->status = FRAME_USED;
  lock_acquire(&frame_lock);
  hash_insert(&frame_hash_map_by_vtop, &(frame->vtop_elem));
  hash_insert(&frame_hash_map_by_fid, &(frame->fid_elem));
  lock_release(&frame_lock);

  /* This function is substitute of palloc_get_page, so should return the same thing. */
  return page;
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

  lock_acquire(&frame_lock);
  hash_delete(&frame_hash_map_by_vtop, &frame->vtop_elem);
  hash_delete(&frame_hash_map_by_fid, &frame->fid_elem);
  palloc_free_page(frame->upage);
  free(frame);
  lock_release(&frame_lock);
}

