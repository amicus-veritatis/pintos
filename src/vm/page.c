#include <hash.h>
#include "lib/kernel/hash.h"

#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/page.h"
#include "vm/frame.h"
unsigned
supp_hash (const struct hash_elem *s_, void *aux UNUSED)
{
  const struct supp_page_table_entry *s = hash_entry(s_, struct supp_page_table_entry, elem);
  /* supt is owned by thread */
  return hash_bytes(&(s->upage), sizeof(s->upage));
}

bool
supp_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
  const struct supp_page_table_entry *a = hash_entry(a_, struct supp_page_table_entry, elem);
  const struct supp_page_table_entry *b = hash_entry(b_, struct supp_page_table_entry, elem);
  return a->upage < b->upage;
}

struct supp_page_table_entry*
search_by_addr (struct thread *t, void * addr)
{
  struct supp_page_table_entry tmp;
  tmp.upage = (void *) pg_round_down(addr);
  struct hash_elem *tmp_elem = hash_find(t->supp_page_table, &(tmp.elem));
  if (tmp_elem == NULL) {
    return NULL;
  }
  return hash_entry(tmp_elem, struct supp_page_table_entry, elem);
}

void
grow_stack (struct thread *t, void *addr) {
  struct supp_page_table_entry *s = malloc(sizeof(struct supp_page_table_entry));
  void *upage = (void *) pg_round_down(addr);
  s->upage = upage;
  s->kpage = NULL;  // Will be set in handle_mm_fault
  s->file = NULL;   // No file associated with stack pages
  s->ofs = 0;
  s->read_bytes = 0;
  s->zero_bytes = PGSIZE;
  s->flags = O_PG_ALL_ZERO | O_WRITABLE | O_PG_MEM;

  hash_insert(t->supp_page_table, &(s->elem));
}

