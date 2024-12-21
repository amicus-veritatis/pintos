#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#define MIN_FILENO 2
#define SENTINEL 1
typedef int pid_t; 
void syscall_init (void);
#ifdef VM
#include "threads/synch.h" 
#include "vm/page.h"
extern struct lock fs_lock;
typedef int mapid_t;
void munmap (mapid_t);
#endif
#endif /* userprog/syscall.h */
