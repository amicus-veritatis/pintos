#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "process.h"
#include "devices/input.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/directory.h"
#ifdef VM
#include "vm/page.h"
#include "vm/frame.h"
#endif
static void syscall_handler (struct intr_frame *);

/* System call functions */
static void halt (void);
static void exit (int);
static int wait (int);
static bool create (const char*, unsigned);
static bool remove (const char *);
static int open (const char *);
static int filesize (int);
static int read (int, void *, unsigned);
static int write (int, const void *, unsigned);
static void seek (int, unsigned);
static unsigned tell (int);
static void close (int);
static pid_t exec(const char* cmd_line);
static int fibonacci (int n);
static int max_of_four_int (int a, int b, int c, int d);
/* End of system call functions */
struct lock fs_lock;

void
syscall_init ()
{
        lock_init(&fs_lock);
        intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Do not trust every pointer no matter what */
static void
syscall_handler (struct intr_frame *f)
{
        uint32_t* esp = (uint32_t*) f->esp;
        check_address(esp);
        int syscall_number = *esp;
        switch (syscall_number) {
                case SYS_HALT:
                        halt();
                        break;
                case SYS_EXIT:
                        /* Never trust anything */
                        check_address(&esp[1]);
                        exit((int) esp[1]);
                        break;
                case SYS_EXEC:
                        f->eax = exec((const char *) esp[1]);
                        break;
                case SYS_WAIT:
                        f->eax = wait((int) esp[1]);
                        break;
                case SYS_CREATE:
                        f->eax = create((const char *) esp[1], (unsigned) esp[2]);
                        break;
                case SYS_REMOVE:
                        f->eax = remove((const char *) esp[1]);
                        break;
                case SYS_OPEN:
                        f->eax = open((const char *) esp[1]);
                        break;
                case SYS_FILESIZE:
                        f->eax = filesize((int) esp[1]);
                        break;
                case SYS_READ:
                        f->eax = read((int) esp[1], (void *) esp[2], (int) esp[3]);
                        break;
                case SYS_WRITE:
                        f->eax = write((int) esp[1], (const void *) esp[2], (int) esp[3]);
                        break;
                case SYS_SEEK:
                        seek((int) esp[1], (unsigned) esp[2]);
                        break;
                case SYS_TELL:
                        f->eax = tell((int) esp[1]);
                        break;
                case SYS_CLOSE:
                        close((int) esp[1]);
                        break;
                case SYS_MMAP:
                        printf("MMAP!\n");
                        break;
                case SYS_MUNMAP:
                        printf("MUNMAP!\n");
                        break;
                case SYS_CHDIR:
                        printf("CHDIR!\n");
                        break;
                case SYS_MKDIR:
                        printf("MKDIR!\n");
                        break;
                case SYS_READDIR:
                        printf("READDIR!\n");
                        break;
                case SYS_ISDIR:
                        printf("ISDIR!\n");
                        break;
                case SYS_INUMBER:
                        printf("INUMBER!\n");
                        break;
                case SYS_FIBONACCI:
                        f->eax = fibonacci((int) esp[1]);
                        break;
                case SYS_MAX_OF_FOUR:
                        f->eax = max_of_four_int((int) esp[1], (int) esp[2], (int) esp[3], (int) esp[4]);
                        break;
                default:
                        exit(-1);
                        break;
        }
}


/* See threads/vaddr.h */
static bool
is_valid_user_vaddr (const void* addr){
        return addr != NULL && is_user_vaddr(addr);
}

static bool
is_valid_fd_num (const int fd_num) {
        return fd_num >= MIN_FILENO && fd_num < FD_MAX_SIZE;
}
#ifdef VM
/*
static inline fs_pin (void *addr, uint32_t size)
{
  for (void *p = addr; p < addr + size; p += PGSIZE) {
    struct frame_table_entry *f = search_by_page(pg_round_down(p));
    f->status = FRAME_PINNED;
    handle_mm_fault(search_by_page(pg_round_down(p)));
  }
}
static inline fs_unpin (void *addr, uint32_t size)
{
  for (void *p = addr; p < addr + size; p += PGSIZE) {
    struct frame_table_entry *f = search_by_page(pg_round_down(p));
    f->status = FRAME_USED;
  }
} */
static inline void fs_pin(const void *addr, uint32_t size)
{
  void *start = addr;
  void *end = addr + size;
  void *upage;

  for (upage = start; upage < end; upage += PGSIZE)
  {
    struct supp_page_table_entry *s = search_by_addr(thread_current(), upage);
    if (s == NULL) {
      exit(-1);
    }
    if (s->kpage == NULL)
    {
      if (!handle_mm_fault(s))
      {
        PANIC("?");
      }
    }
    ASSERT(s->kpage != NULL);
    set_pinned(s->kpage, true);
  }
}

static inline void fs_unpin(const void *addr, uint32_t size)
{
  void *start = addr;
  void *end = addr + size;
  void *upage;

  for (upage = start; upage < end; upage += PGSIZE)
  {
    struct supp_page_table_entry *s = search_by_addr(thread_current(), upage);
    if (s == NULL) {
      exit(-1);
    }
    if (s->kpage != NULL) {
      set_pinned(s->kpage, false);
    }
  }
}

#endif
/* Two conditions that terminate the process
 * 1. addr is not a valid user vaddr
 * 2. Virtual memory related
 */
void check_address(const void *addr) {
#ifndef VM
  if (!is_valid_user_vaddr(addr) || pagedir_get_page (thread_current() -> pagedir,addr) == NULL) {
                exit(-1);
        }
#else
  if (!is_valid_user_vaddr(addr)) {
    exit(-1);
  }
#endif
}

void check_fd_num (const int fd) {
        if (!is_valid_fd_num(fd)) {
                exit(-1);
        }
  struct thread *t = thread_current();
  if (t->fd[fd] == NULL) {
    exit(-1);
  }
}
/*
 * Get current thread and shut down it.
 * Terminates the current user program,
 * returning status to the kernel.
 * If the process’s parent waits for it (see below),
 * this is the status that will be returned.
 * Conventionally, a status of 0 indicates success and nonzero values indicate errors.
 */
void
exit (int status)
{
        struct thread* cur = thread_current();
        cur -> exit_status = status;
        cur -> flags |= O_EXITED;
        printf("%s: exit(%d)\n", thread_name(), status);
        thread_exit();
}

int
wait (pid_t pid)
{
        return process_wait(pid);
}

bool
create (const char *file_name, unsigned size)
{
  lock_acquire(&fs_lock);
        // Do not trust anything
        check_address(file_name);
        bool ret = filesys_create(file_name, size);
  lock_release(&fs_lock);
  return ret;
}

bool
remove (const char *file_name)
{
        // Do not trust anything
  lock_acquire(&fs_lock);
        check_address(file_name);
        bool ret = filesys_remove(file_name);
  lock_release(&fs_lock);
  return ret;
}

int
open (const char* file_name)
{
        // Do not trust anything
        check_address(file_name);
        lock_acquire(&fs_lock);
        struct file *f = filesys_open(file_name);
        if (f == NULL) {
                lock_release(&fs_lock);
                return -1;
        }
        int cur_fd = MIN_FILENO;
        while (cur_fd < FD_MAX_SIZE) {
                if (thread_current()->fd[cur_fd] == NULL) {
                        break;
                }
                cur_fd++;
        }
        if (cur_fd >= FD_MAX_SIZE) {
                lock_release(&fs_lock);
                return -1;
        }
        struct thread *t = thread_current();
        if (strcmp(t->name, file_name) == 0) {
                file_deny_write(f);
        }
        t->fd[cur_fd] = f;
        lock_release(&fs_lock);
        return cur_fd;
}

int
filesize (int fd)
{
        check_fd_num(fd);
        lock_acquire(&fs_lock);
        struct thread *t = thread_current();
        int ret = file_length(t->fd[fd]);
        lock_release(&fs_lock);
        return ret;
}

void
seek (int fd, unsigned position)
{
        check_fd_num(fd);
        lock_acquire(&fs_lock);
        file_seek(thread_current()->fd[fd], position);
        lock_release(&fs_lock);
}

unsigned
tell (fd)
{
        check_fd_num(fd);
        unsigned status;
        lock_acquire(&fs_lock);
        status = file_tell(thread_current()->fd[fd]);
        lock_release(&fs_lock);
        return status;
}

/*
 * return with 0 if user is either trying to
 * write into stdin or cause out-of-range error
 */
int
write (int fd, const void *buffer, unsigned size)
{
        check_address(buffer);
        if (fd == STDIN_FILENO) {
                return 0;
        } else if (fd == STDOUT_FILENO) {
                putbuf(buffer, size);
                return size;
        }
        else if (fd >= MIN_FILENO && fd < FD_MAX_SIZE) {
                /* fprint has not been implemented yet! */
                lock_acquire(&fs_lock);
#ifdef VM
    fs_pin(buffer, size);
#endif
                struct thread *t = thread_current();
                int ret = 0;
                if (t->fd[fd] != NULL) {
                        ret = file_write(t->fd[fd], buffer, size);
                }
#ifdef VM
    fs_unpin(buffer, size);
#endif
                lock_release(&fs_lock);
                return ret;
        }
        return 0;
}

/*
 * return with -1 if user is either trying to
 * read stdout  or cause out-of-range error
 * for input_getc(), see src/devices/input.h
 */
int read(int fd, void *buffer, unsigned size) {
        check_address(buffer);
        check_address(buffer+size-1);
        if (fd == STDOUT_FILENO) {
                return -1;
        } else if (fd == STDIN_FILENO) {
                /* We do not check \0
                 * Trust programmers! */
                lock_acquire(&fs_lock);
#ifdef VM
    fs_pin(buffer, size);
#endif
                char *buf = buffer;
    *buf = input_getc();
#ifdef VM
    fs_unpin(buffer, size);
#endif
                lock_release(&fs_lock);
                return size;
        }
        else if (fd >= MIN_FILENO && fd < FD_MAX_SIZE) {
                lock_acquire(&fs_lock);
#ifdef VM
    fs_pin(buffer, size);
#endif
                struct thread *t = thread_current();
                if (t->fd[fd] == NULL) {
                        lock_release(&fs_lock);
                        return -1;
                }
                int f = file_read(t->fd[fd], buffer, size);
#ifdef VM
    fs_unpin(buffer, size);
#endif
                lock_release(&fs_lock);
                return f;
        }
        return -1;
}

/* See src/devicees/shutdown.c */
void
halt ()
{
        shutdown_power_off ();
}

/* exit the process if pointer points to invalid address
 * do not trust pointer
 * Also acquire and release fs_lock because
 * process_execute() calls load() and load() uses file system.
 */
pid_t
exec (const char *cmd_line)
{
        check_address(cmd_line);
        lock_acquire(&fs_lock);
        /* Avoid race condition. */
        char *cmd_line_copy = palloc_get_page(0);
        if (cmd_line_copy == NULL) {
                return -1;
        }
        strlcpy(cmd_line_copy, cmd_line, PGSIZE);

        tid_t ret = process_execute(cmd_line_copy);

        palloc_free_page(cmd_line_copy);

        lock_release(&fs_lock);
        if (ret == TID_ERROR) {
                return -1;
        }

        return ret;
}

void
close (int fd)
{
        lock_acquire(&fs_lock);
        struct thread *t = thread_current();
        if (t->fd[fd] == NULL) {
                lock_release(&fs_lock);
                return;
        }
        file_close(t->fd[fd]);
        t->fd[fd] = NULL;
        lock_release(&fs_lock);
        return;
}

/* Simple iterative implementation */
int
fibonacci (int n)
{
        if (n<0) {
          exit (-1);
        }
        else if (n<=1) {
          return n;
        }

        int k = 0;
        int p = 1;
        int q = 0;
        for (int i = 2; i<=n; i++) {
            k = p + q;
            q = p;
            p = k;
        }
        return k;
}
int
max_of_four_int (int a, int b, int c, int d) {
        int ab, cd;
        ab = a > b ? a : b;
        cd = c > d ? c : d;
        return ab > cd ? ab : cd;
}
