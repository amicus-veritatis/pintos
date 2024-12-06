#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <bitmap.h>
void swap_in(size_t, void *);
void swap_init(void);
size_t swap_out(void *);
void swap_free(size_t);
#endif
