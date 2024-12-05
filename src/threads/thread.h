#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/synch.h"

#ifndef USERPROG
/* Project #3. */
extern bool thread_prior_aging;
#endif

#ifdef VM
#include "vm/page.h"
#endif

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;

typedef int float32_t;

#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */
#define FD_MAX_SIZE 128

/* load status. */
#define LOAD_FAIL -1
#define LOAD_INIT 0
#define LOAD_SUCCESS 1

#define O_PARENT_WAITING 0x01
#define O_EXITED 0x02
#define O_ORPHAN 0x04

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    int nice;				/* Nice value. */
    float32_t recent_cpu;		/* Recently used cpu */
    struct list_elem allelem;           /* List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */
    int64_t ticks;
#ifdef USERPROG
    /* Owned by userprog/process.c. */

    uint32_t *pagedir;                  /* Page directory. */
    struct thread *parent;
    int exit_status;	
    /*
     * O_PARENT_WAITING(0x01): Parent is waiting
     * O_EXITED(0x02): Current process has been exited
     * O_ORPHAN(0x04): Current process is an orphan
     */
    uint8_t flags;
    /* child threads */
    int8_t load_status;
    struct semaphore load_sema;

    struct list children;
    struct list_elem child_elem;
    struct semaphore wait_sema;
    struct semaphore remove_sema;
    /* According to Pintos Manual 3.4.2. System Calls FAQ,
     * the usage of struct file *fd is discrouaged.
     * but for now, we just choose to use it.
     * maybe needed to be refactored.
     */
    
#endif
#ifdef VM
    struct hash *supp_page_table;
    void *esp;
    struct file *file;
#endif
    struct file *fd[FD_MAX_SIZE]; /* file descriptor table. */
    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
    
  };

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);
bool cmp(const struct list_elem* a, const struct list_elem* b, void *aux);
int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void update_recent_cpu (struct thread *, void *);
void update_mlfqs_priority (struct thread *, void *);
bool is_idle_thread(struct thread *);
#endif /* threads/thread.h */
