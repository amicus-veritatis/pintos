#include <bitmap.h>
#include "threads/vaddr.h"
#include "devices/block.h"
#include "vm/swap.h"
#include "vm/frame.h"
#include "vm/page.h"
#define MAX_BLOCKS (PGSIZE / BLOCK_SECTOR_SIZE)


static struct bitmap *swap_bitmap;
static struct lock swap_lock;
void
swap_init ()
{
  lock_init(&swap_lock);
  size_t swap_size = block_size(block_get_role(BLOCK_SWAP)) / MAX_BLOCKS;
  swap_bitmap = bitmap_create(swap_size);
  bitmap_set_all(swap_bitmap, true);
}

void
swap_in (size_t idx, void * addr)
{
  lock_acquire(&swap_lock);
  ASSERT (idx != -1);
  struct block *swap_disk = block_get_role(BLOCK_SWAP);
  for (size_t i=0; i<MAX_BLOCKS; i++) {
    block_read(swap_disk, MAX_BLOCKS * idx + i, addr + BLOCK_SECTOR_SIZE * i);
  }
  bitmap_flip(swap_bitmap, idx);
  lock_release(&swap_lock);
}

size_t swap_out (void *addr)
{
  lock_acquire(&swap_lock);
  size_t idx = bitmap_scan_and_flip(swap_bitmap, 0, 1, true);
  if (idx == BITMAP_ERROR) {
    PANIC("Swap space exhausted");
  }
  for (size_t i = 0; i < MAX_BLOCKS; i++) {
    block_write(block_get_role(BLOCK_SWAP), idx * MAX_BLOCKS + i, addr + BLOCK_SECTOR_SIZE * i);
  }
  lock_release(&swap_lock);
  return idx;
}

void
swap_free (size_t idx)
{
  lock_acquire(&swap_lock);
  bitmap_flip(swap_bitmap, idx);
  lock_release(&swap_lock);
}
