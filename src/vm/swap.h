#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <hash.h>
#include <bitmap.h>
#include <list.h>
#include "threads/synch.h"
void swap_in(size_t, void *);
void swap_init(void);
size_t swap_out(void *);
#endif
