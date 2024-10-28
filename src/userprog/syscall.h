#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#define MIN_FILENO 2
#define SENTINEL 1
typedef int pid_t; 
void syscall_init (void);
static void close (int);
#endif /* userprog/syscall.h */
