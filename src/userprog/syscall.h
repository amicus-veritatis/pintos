#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#define STDERR_FILENO 2
#define SENTINEL 1
typedef int pid_t; 
void syscall_init (void);
int fibonacci (int n);
int max_of_four_int (int a, int b, int c, int d);
#endif /* userprog/syscall.h */
