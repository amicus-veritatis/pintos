#include <hash.h>
#include "lib/kernel/hash.h"
#include <string.h>
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
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
  memset(&tmp, 0, sizeof(tmp));
  tmp.upage = (void *) pg_round_down(addr);
  if (t->supp_page_table == NULL) {
    return NULL;
  }
  struct hash_elem *tmp_elem = hash_find(t->supp_page_table, &(tmp.elem));
  if (tmp_elem == NULL) {
    return NULL;
  }
  struct supp_page_table_entry *s = hash_entry(tmp_elem, struct supp_page_table_entry, elem);
  return s;
}

struct supp_page_table_entry*
search_by_addr_without_pg_round_down (struct thread *t, void * addr)
{
  struct supp_page_table_entry tmp;
  memset(&tmp, 0, sizeof(tmp));
  tmp.upage = (void *) addr;
  if (t->supp_page_table == NULL) {
    return NULL;
  }
  struct hash_elem *tmp_elem = hash_find(t->supp_page_table, &(tmp.elem));
  if (tmp_elem == NULL) {
    return NULL;
  }
  struct supp_page_table_entry *s = hash_entry(tmp_elem, struct supp_page_table_entry, elem);
  return s;
}


inline void
print_spte_entry (struct supp_page_table_entry *s)
{
  printf("supp_page_table_entry s:\n");
  printf("\tupage:\t%p\n", s->upage);
  printf("\tkpage:\t%p\n", s->kpage);
  printf("\tflags: %d\n", s->flags);
  printf("\t\tO_DIRTY: %d, %d\n", O_DIRTY, s->flags & O_DIRTY);
  printf("\t\tO_WRITABLE: %d, %d\n", O_WRITABLE, s->flags & O_WRITABLE);
  printf("\t\tO_PG_ALL_ZERO: %d, %d\n", O_PG_ALL_ZERO, s->flags & O_PG_ALL_ZERO);
  printf("\t\tO_PG_FS: %d, %d\n", O_PG_FS, s->flags & O_PG_FS);
  printf("\t\tO_PG_SWAP: %d, %d\n", O_PG_SWAP, s->flags & O_PG_SWAP);
  printf("\t\tO_PG_MEM: %d, %d\n", O_PG_MEM, s->flags & O_PG_MEM);
  printf("\tswap_idx:\t%d\n", s->swap_idx);
}
void
grow_stack (struct thread *t, void *addr) {
  struct supp_page_table_entry *s = malloc(sizeof(struct supp_page_table_entry));
  void *upage = (void *) pg_round_down(addr);
  s->upage = upage;
  s->kpage = NULL;
  s->file = NULL;
  s->flags = O_PG_ALL_ZERO | O_WRITABLE;
  s->swap_idx = -1;
  hash_insert(t->supp_page_table, &(s->elem));
}

void
supp_destroy (struct hash_elem *s_, void *aux UNUSED)
{
    struct supp_page_table_entry *s = hash_entry(s_, struct supp_page_table_entry, elem);
    if ((s->flags & O_PG_MASK) == O_PG_MEM && s->kpage != NULL) {
        frame_free_page(s->kpage);
    }
    if ((s->flags & O_PG_SWAP) && s->swap_idx != (size_t) -1) {
      swap_free(s->swap_idx);
    }
    free(s);
}
