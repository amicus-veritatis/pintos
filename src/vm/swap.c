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
  uint8_t *buffer = (uint8_t *) addr;
  for (size_t i=0; i<MAX_BLOCKS; i++) {
    block_read(block_get_role(BLOCK_SWAP), MAX_BLOCKS * idx + i, buffer + BLOCK_SECTOR_SIZE * i);
  }
  bitmap_set(swap_bitmap, idx, true);
  lock_release(&swap_lock);
}

size_t swap_out (void *addr)
{
  lock_acquire(&swap_lock);
  size_t idx = bitmap_scan(swap_bitmap, 0, 1, true);
  if (idx == BITMAP_ERROR) {
    PANIC("Swap space exhausted");
  }
  uint8_t *buffer = (uint8_t *) addr;
  for (size_t i = 0; i < MAX_BLOCKS; i++) {
    block_write(block_get_role(BLOCK_SWAP), idx * MAX_BLOCKS + i, buffer + BLOCK_SECTOR_SIZE * i);
  }
  bitmap_set(swap_bitmap, idx, false);
  lock_release(&swap_lock);
  return idx;
}

void
swap_free (size_t idx)
{
  lock_acquire(&swap_lock);
  bitmap_set(swap_bitmap, idx, true);
  lock_release(&swap_lock);
}

/* 
void
swap_in (size_t idx, void * addr)
{
  lock_acquire(&swap_lock);
  for (size_t i=0; i<MAX_BLOCKS; i++) {
    block_read(block_get_role(BLOCK_SWAP), MAX_BLOCKS * idx + i, BLOCK_SECTOR_SIZE*i + addr);
  }
  bitmap_set(swap_bitmap, idx, true);
  lock_release(&swap_lock);
}

size_t swap_out (void *addr)
{
  lock_acquire(&swap_lock);
  size_t idx = bitmap_scan(swap_bitmap, 0, 1, 1);
  if (idx == BITMAP_ERROR) {
    // Handle the error, possibly by killing the process or freeing up swap space
    PANIC("Swap space exhausted");
}
  for (size_t i = 0; i <MAX_BLOCKS; i++) {
    block_write(block_get_role(BLOCK_SWAP), idx * MAX_BLOCKS + i, addr + BLOCK_SECTOR_SIZE * i);
  }
  bitmap_set(swap_bitmap, idx, false);
  lock_release(&swap_lock);
  return idx;
}
*/
