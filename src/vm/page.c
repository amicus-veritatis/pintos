#include <hash.h>
#include "lib/kernel/hash.h"

#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "vm/page.h"

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


