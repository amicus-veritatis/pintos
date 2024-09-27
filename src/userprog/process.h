#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

#define ARG_DELIM " "
#define SENTINEL 1
#define WORD_SIZE sizeof(uint32_t)
typedef int pid_t;

struct process_info {
	char *fn_copy;
	struct thread* parent;
	struct thread* self;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
