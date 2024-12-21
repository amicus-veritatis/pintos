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
#include "vm/swap.h"
#define MAX(a,b) (a > b ? a : b)
#define MIN(a,b) (a > b ? b : a)
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
#ifdef VM
static mapid_t mmap (int, void *);
void munmap (mapid_t);
#endif
/* End of system call functions */
struct lock fs_lock;

void
syscall_init ()
{
        lock_init(&fs_lock);
        intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static inline void
syscall_lock_acquire (const char *s) {
  printf("[%s] Thread %s acquiring fs_lock (at %p)\n", s, thread_current()->name, &fs_lock);
  lock_acquire(&fs_lock);
  printf("[%s] Thread %s acquired fs_lock (at %p)\n", s, thread_current()->name, &fs_lock);
}

static inline void
syscall_lock_release (const char *s) {
  printf("[%s] Thread %s releasing fs_lock (at %p)\n", s, thread_current()->name, &fs_lock);
  lock_release(&fs_lock);
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
#ifdef VM
                        f->eax = mmap((int) esp[1], (void *) esp[2]);
#else
                        printf("MMAP!");
#endif
                        break;
                case SYS_MUNMAP:
#ifdef VM
                        munmap((mapid_t) esp[1]);
#else
                        printf("MUNMAP!");
#endif
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

static inline bool
is_consecutive_address (struct thread *t, size_t file_size, void * addr)
{
  for (size_t ofs = 0; ofs < file_size; ofs += PGSIZE) {
    if (search_by_addr(t, addr + ofs)) {
      return false;
    }
  }
  return true;
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
  //syscall_lock_acquire("create");
  lock_acquire(&fs_lock);
  // Do not trust anything
  check_address(file_name);
  bool ret = filesys_create(file_name, size);
  lock_release(&fs_lock);
  //syscall_lock_release("create");
  return ret;
}

bool
remove (const char *file_name)
{
        // Do not trust anything
  lock_acquire(&fs_lock);
  //syscall_lock_acquire("remove");
  check_address(file_name);
        bool ret = filesys_remove(file_name);
  lock_release(&fs_lock);
  //syscall_lock_release("remove");
  return ret;
}

int
open (const char* file_name)
{
        // Do not trust anything
        check_address(file_name);
        //syscall_lock_acquire("open");
        lock_acquire(&fs_lock);
        struct file *f = filesys_open(file_name);
        if (f == NULL) {
                //syscall_lock_release("open");
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
                //syscall_lock_release("open");
                lock_release(&fs_lock);
                return -1;
        }
        struct thread *t = thread_current();
        if (strcmp(t->name, file_name) == 0) {
                file_deny_write(f);
        }
        //syscall_lock_release("open");
        lock_release(&fs_lock);
        t->fd[cur_fd] = f;
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
        //syscall_lock_acquire("seek");
        lock_acquire(&fs_lock);
        file_seek(thread_current()->fd[fd], position);
        lock_release(&fs_lock);
        //syscall_lock_release("seek");
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
#ifdef VM
    fs_pin(buffer, size);
#endif
                struct thread *t = thread_current();
                int ret = 0;
                if (t->fd[fd] != NULL) {
                        lock_acquire(&fs_lock);
                        ret = file_write(t->fd[fd], buffer, size);
                        lock_release(&fs_lock);
                }
#ifdef VM
    fs_unpin(buffer, size);
#endif
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
#ifdef VM
    fs_pin(buffer, size);
#endif
                char *buf = buffer;
    *buf = input_getc();
#ifdef VM
    fs_unpin(buffer, size);
#endif
                return size;
        }
        else if (fd >= MIN_FILENO && fd < FD_MAX_SIZE) {
#ifdef VM
    fs_pin(buffer, size);
#endif
                struct thread *t = thread_current();
                if (t->fd[fd] == NULL) {
                        return -1;
                }
                lock_acquire(&fs_lock);
                int f = file_read(t->fd[fd], buffer, size);
                lock_release(&fs_lock);
#ifdef VM
    fs_unpin(buffer, size);
#endif
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
        /* Avoid race condition. */
        char *cmd_line_copy = palloc_get_page(0);
        if (cmd_line_copy == NULL) {
                return -1;
        }
        strlcpy(cmd_line_copy, cmd_line, PGSIZE);

        tid_t ret = process_execute(cmd_line_copy);

        palloc_free_page(cmd_line_copy);

        if (ret == TID_ERROR) {
                return -1;
        }

        return ret;
}

void
close (int fd)
{
        //syscall_lock_acquire("close");
        lock_acquire(&fs_lock);
        struct thread *t = thread_current();
        if (t->fd[fd] == NULL) {
                lock_release(&fs_lock);
                return;
        }
        file_close(t->fd[fd]);
        t->fd[fd] = NULL;
        lock_release(&fs_lock);
        //syscall_lock_release("close");
        return;
}

#ifdef VM
mapid_t
mmap (int fd, void *addr)
{
  // printf("[DEBUG] fd=%d, addr=%p\n", fd, addr);
  if (pg_ofs(addr) || !is_valid_user_vaddr(addr)) {
    // printf("[DEBUG] fail: address not page aligned or invalid %p\n", addr);
    return -1;
  }
  if (!is_valid_fd_num(fd)) {
    // printf("[DEBUG] fail: invalid fd\n");
    return -1;
  }
  struct thread *t = thread_current();
  struct file *f = NULL;
  if (t->fd[fd] == NULL) {
    return -1;
  }
  if (search_by_addr(t, addr)) {
    // printf("[DEBUG] fail: address already mapped: %d, %p\n", t->tid, addr);
    return -1;
  }
  //syscall_lock_acquire("mmap");
  lock_acquire(&fs_lock);
  size_t file_size = file_length(t->fd[fd]);
  if (file_size == 0) {  
    lock_release(&fs_lock);
    //syscall_lock_release("mmap"); 
    return -1;
  }
  f = file_reopen(t->fd[fd]);
  if (f == NULL) {
    lock_release(&fs_lock);
    //syscall_lock_release("mmap"); 
    return -1;
  }
  if (!is_consecutive_address(t, file_size, addr)) {
    // printf("[DEBUG] fail: not consecutive: %d, %d, %p\n", t->tid, file_size, addr);
    //syscall_lock_release("mmap"); 
    lock_release(&fs_lock);
    return -1;
  }
  lock_release(&fs_lock);
  //syscall_lock_release("mmap"); 
  for (size_t ofs = 0; ofs < file_size; ofs += PGSIZE) {
    size_t read_bytes = MIN(file_size - ofs, PGSIZE);
    size_t zero_bytes = PGSIZE - read_bytes;
    struct supp_page_table_entry *s = malloc(sizeof(struct supp_page_table_entry));
    // kernel pool is full, nothing to do 
    if (s == NULL) {
      continue;
    }
    s->upage = addr + ofs;
    s->kpage = NULL;
    s->flags = 0;
    s->flags |= O_PG_FS | O_WRITABLE;
    s->file = f;
    s->ofs = ofs;
    s->read_bytes = MIN(file_size - ofs, PGSIZE);
    s->zero_bytes = PGSIZE - s->read_bytes;
    s->swap_idx = -1;
    hash_insert(t->supp_page_table, &(s->elem));
  }

  struct mmap_entry *m = malloc(sizeof(struct mmap_entry));
  memset(m, 0, sizeof(struct mmap_entry));
  m->mapid = t->mapid++;
  m->file = f;
  m->upage = addr;
  m->file_size = file_size;
  mapid_t mapid = m->mapid;
  list_push_back(&(t->mmap), &(m->elem));
  // printf("[DEBUG] success: mapid=%d\n", mapid);
  return mapid;
}

static inline struct mmap_entry*
search_by_mapid(struct thread *t, mapid_t mapid)
{
  if (list_empty(&(t->mmap))) {
    return NULL;
  }
  for (struct list_elem *it = list_begin(&(t->mmap)); it != list_end((&t->mmap)); it = list_next(it)) {
    struct mmap_entry *m = list_entry(it, struct mmap_entry, elem);
    if (m->mapid == mapid) {
      return m;
    }
  }
  return NULL;
}

void
munmap (mapid_t mapping)
{
  struct thread *t = thread_current();
  struct mmap_entry *m = search_by_mapid(t,mapping);
  ASSERT (m != NULL);
  if (m == NULL) {
    exit(-1);
  }
  lock_acquire(&fs_lock);
  //syscall_lock_acquire("munmap");
  size_t file_size = m->file_size;
  for (size_t ofs = 0; ofs < file_size ; ofs += PGSIZE) {
    void *addr = m->upage + ofs;
    size_t bytes = MIN(file_size - ofs, PGSIZE);
    struct supp_page_table_entry *s = search_by_addr(t, addr);
    ASSERT (s != NULL);
    if (s->flags & O_PG_MEM) {
      ASSERT(s->kpage != NULL);
      set_pinned(s->kpage, true);
    }
    uint8_t flags = s->flags & O_PG_MASK;
    switch (flags) {
      case O_PG_MEM:
        if (s->flags & O_DIRTY || pagedir_is_dirty(t->pagedir, s->upage)) {
          file_write_at (m->file, s->upage, bytes, ofs);
        }
        // printf("[munmap] Tryting to free %p\n", s->kpage);
        frame_free_page(s->kpage);
        break;
      case O_PG_SWAP:
        if (s->flags & O_DIRTY || pagedir_is_dirty(t->pagedir, s->upage)) {
          void *new_page = palloc_get_page(0);
          swap_in(s->swap_idx, new_page);
          file_write_at(m->file, new_page, PGSIZE, ofs);
          palloc_free_page(new_page);
        } else {
          ASSERT(s->swap_idx != -1);
          swap_free(s->swap_idx);
        }
        break;
      case O_PG_FS:
        break;
      case O_PG_ALL_ZERO:
        PANIC("??");
      default:
        PANIC("??????");
    }
    hash_delete(t->supp_page_table, &(s->elem));
  }
  list_remove(&m->elem);
  file_close(m->file);
  lock_release(&fs_lock);
  //syscall_lock_release("munmap");
  free(m);
}
#endif
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
