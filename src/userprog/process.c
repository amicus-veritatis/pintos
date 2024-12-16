#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#ifdef VM
#include <hash.h>
#include "lib/kernel/hash.h"
#include "vm/swap.h"
#include "vm/frame.h"
#include "vm/page.h"
#endif
#ifdef VM
#define get_page(flags) palloc_get_page(flags)
#define free_page(page) palloc_free_page(page)
#else
#define get_page(flags) palloc_get_page(flags)
#define free_page(page) palloc_free_page(page)
#endif

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
  char *fn_copy;
  tid_t tid;
  char *save_ptr = NULL;

  fn_copy = get_page (0);
  if (fn_copy == NULL) {
        return TID_ERROR;
  }
  strlcpy (fn_copy, file_name, PGSIZE);
  /* Make a pinfo and put copy of FILE_NAME inside pinfo.
     Otherwise there's a race between the caller and load(). */

  /* Information about child process. */
  struct process_info *pinfo = get_page(0);
  if (pinfo == NULL) {
        free_page(fn_copy);
        return TID_ERROR;
  }
  pinfo->fn_copy = fn_copy;

  /* The process calling the exec() is said to be a parent process.
   * Thus, it's reasonable to assume that current running process is the
   * parent process. */
  struct thread* cur = thread_current();
  pinfo->parent = cur;
  pinfo->self = NULL;
  /* Loading in progress */
  cur->load_status = LOAD_INIT;

  /* Avoid race condition */
  char *fn_copy_copy = get_page (0);
  if (fn_copy_copy == NULL) {
          free_page (fn_copy);
          free_page (pinfo);
          return TID_ERROR;
  }
  strlcpy(fn_copy_copy, file_name, PGSIZE);
  file_name = strtok_r(fn_copy_copy, " ", &save_ptr);
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, pinfo);
  if (tid == TID_ERROR) {
    free_page (fn_copy);
    free_page (fn_copy_copy);
    free_page (pinfo);
    return TID_ERROR;
  }
  /* Wait until thread is actually created */
  sema_down(&(cur->load_sema));
  if (cur->load_status == LOAD_FAIL) {
    tid = TID_ERROR;
  }

  if (pinfo->self != NULL) {
    list_push_back(&(cur->children), &(pinfo->self->child_elem));
  }
  free_page(fn_copy);
  free_page(fn_copy_copy);
  free_page(pinfo);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *pinfo_)
{
  struct intr_frame if_;
  bool success;
  struct process_info *pinfo = pinfo_;
  char *file_name = pinfo->fn_copy;
  /* A new thread is already created and running via thread_create() */
  struct thread *cur = thread_current();
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  /* load the binary. */
  success = load (file_name, &if_.eip, &if_.esp);

  struct thread* parent = pinfo->parent;
  if (success) {
    cur->tid = (pid_t)(cur->tid);
  } else {
    cur->tid = TID_ERROR;
  }
  cur->parent = parent;
  if (parent != NULL) {
      /* If load () failed, inform the parent */
      parent->load_status = success ? LOAD_SUCCESS : LOAD_FAIL;
      /* Process is now created or failed to do so; parent can do what it wants to do */
      if (success) {
        pinfo->self = cur;
      }
      /* The parent process is waiting... */
      sema_up(&(parent->load_sema));
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
   asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
   NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
    struct list_elem *it;
    struct thread* cur = thread_current();
    struct list *children = &cur->children;
    struct thread *child = NULL;
    /* if TID is invalid */
    if (child_tid == NULL) {
            return -1;
    }
    /* there is no lambda function in c so we do this every time */
    for (it=list_begin(children); it != list_end(children); it = list_next(it)) {
            struct thread *t = list_entry(it, struct thread, child_elem);
            if (t->tid == child_tid) {
                    child = t;
                    break;
            }
    }

    /*
     * 1. There is no child process with matching tid.
     * 2. Parent already called wait() on the child
     */

    if (child == NULL || (child->flags & O_PARENT_WAITING) != 0) {
        return -1;
    } else {
        /* Parent will wait */
        child->flags |= O_PARENT_WAITING;
    }
    int ret;
    /* Make parent wait */
    if ((child->flags & O_EXITED) == 0) {
        sema_down(&(child->wait_sema));
    }
    ret = child -> exit_status;
    list_remove(&(child->child_elem));
    sema_up(&(child->remove_sema));
    return ret;
}
/* Free the current process's resources. */

void
process_exit (void)
{
   struct thread *cur = thread_current ();

   for (int fd=MIN_FILENO; fd<FD_MAX_SIZE; fd++) {
    struct file *f = cur->fd[fd];
    if (f != NULL) {
            file_close(cur->fd[fd]);
        f= NULL;
    }
   }
   /* Clean up the children threads */
   struct list *children = &cur->children;
   while(!list_empty(children)) {
        struct list_elem *el = list_pop_back(children);
        struct thread *t = list_entry(el, struct thread, child_elem);
        if ((t->flags & O_EXITED) == 0) {
           t->flags |= O_ORPHAN;
           t->parent = NULL;
        }
   }
#ifdef VM
  if (cur->supp_page_table != NULL) {
    hash_destroy(cur->supp_page_table, supp_destroy);
    free(cur->supp_page_table);
    cur->supp_page_table = NULL;
  }
#endif
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
#ifdef VM
  if (cur->file != NULL) {
    file_allow_write(cur->file);
    file_close(cur->file);
  }
#endif


   /* We're done with this process */
   cur->flags |= O_EXITED;

   /* Make this process actually die, while preventing
    * it from generating another process. */
   sema_up(&(cur->wait_sema));
   sema_down(&(cur->remove_sema));
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

#ifdef VM
  t->supp_page_table = malloc(sizeof(struct hash));
  if (t->supp_page_table == NULL) {
    goto done;
  }
  hash_init(t->supp_page_table, supp_hash, supp_less, NULL);
#endif
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  char* argv[128];
  char* arg, *save_ptr;
  int argc = 0;

  arg = strtok_r(file_name, ARG_DELIM, &save_ptr);
  while (arg) {
    argv[argc++] = arg;
    arg = strtok_r(NULL, ARG_DELIM, &save_ptr);
  }


  /* Open executable file. */
  file = filesys_open (argv[0]);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }
#ifdef VM
  t->file = file;
  file_deny_write(file);
#endif

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Push arguments. */
  for (i=argc-1; i>=0; i--){
    int arg_len = strlen(argv[i]) + SENTINEL;
    *esp = (uint8_t *)(*esp) - arg_len;
    memcpy(*esp, argv[i], arg_len);
    argv[i] = *esp;
  }

  /* Do some pointer arithmetics. */
  uint32_t padding_size = (uintptr_t)(*esp) % WORD_SIZE;
  if (padding_size != 0) {
    *esp -= padding_size;
    memset(*esp, 0, padding_size);
  }
  /* Terminate with 0 */
  *esp = (uint8_t *)(*esp) - sizeof(char *);
  memset(*esp, 0, sizeof(char *));

  for (i=argc-1; i>=0; i--) {
      /* Normal string */
      *esp = (uint8_t *)(*esp) - sizeof(char *);
      memcpy(*esp, &argv[i], sizeof(char *));
  }

  /* Save the address of argv[0] */
  void *argv_addr = *esp;

  /*
  push argv.
  as we assigned &argv[0] to *argv_addr, argv_addr should contain
  the address of &argv[0].
  */
  *esp = (uint8_t *)(*esp) - sizeof(void *);
  memcpy(*esp, &argv_addr, sizeof(void *));
  /* Push argc */
  *esp = (uint8_t *)(*esp) - sizeof(int);
  memcpy(*esp, &argc, sizeof(int));

  /* Push fake return address */
  *esp = (uint8_t *)(*esp) - sizeof(char **);
  memset(*esp, 0, sizeof(char **));

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
#ifndef VM
  file_close (file);
#endif
  return success;
}
/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);
#ifndef VM
  file_seek (file, ofs);
#endif
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

#ifndef VM
      /* Get a page of memory. */
      uint8_t *kpage = get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);
      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          free_page (kpage);
          return false;
        }
#else
      struct supp_page_table_entry *s = malloc(sizeof(struct supp_page_table_entry));
      if (s == NULL) {
        return false;
      }
      s->upage = upage;
      s->kpage = NULL;
      s->flags = 0;
      s->swap_idx = -1;
      if (page_read_bytes == 0) {
        s->flags = O_PG_ALL_ZERO; // Mark as zero-initialized
      } else {
        s->flags = O_PG_FS;       // Mark as file-backed
        s->read_bytes = page_read_bytes;
        s->zero_bytes = page_zero_bytes;
        s->file = file;
        s->ofs = ofs;
      }
      if (writable) {
        s->flags |= O_WRITABLE;
      }
      struct thread *t = thread_current();
      hash_insert(t->supp_page_table, &(s->elem));
#endif


      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
#ifdef VM
      ofs += page_read_bytes;
#endif
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;
#ifndef VM
  kpage = get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      if (install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true)) {
        *esp = PHYS_BASE;
      }
      else {
        free_page (kpage);
      }
    }
  return true;
#else
  void *upage = ((uint8_t *) PHYS_BASE) - PGSIZE;
  struct supp_page_table_entry *s = malloc(sizeof(struct supp_page_table_entry));

  if (s == NULL) {
    return success;
  }
  s->swap_idx = -1;
  s->upage = upage;
  s->flags = 0;
  s->kpage = NULL;
  s->file = NULL;
  s->flags |= O_WRITABLE;
  s->flags |= O_PG_ALL_ZERO;
  struct thread *t = thread_current();
  hash_insert(t->supp_page_table, &(s->elem));
  *esp = PHYS_BASE;
  success = true;
  return success;
#endif
}
#ifdef VM
bool
handle_mm_fault (struct supp_page_table_entry *s)
{
  uint8_t flags = s->flags & O_PG_MASK;
  bool success = false;
  if (flags == O_PG_MEM) {
    return true;
  }
  void *new_page = frame_get_page(PAL_USER, s->upage);
  ASSERT (new_page != NULL);
  switch (flags) {
    case O_PG_ALL_ZERO:
      memset(new_page, 0, PGSIZE);
      success = true;
      break;
    case O_PG_FS:
      file_seek(s->file, s->ofs);
      if (file_read(s->file, new_page, s->read_bytes) != (int) s->read_bytes) {
        frame_free_page(new_page);
        return false;
      }
      memset(new_page + s->read_bytes, 0, s->zero_bytes);
      success = true;
      break;
    case O_PG_SWAP:
      swap_in(s->swap_idx, new_page);
      success = true;
      break;
    default:
      return success;
  }

  if (success) {
    bool writable = (s->flags & O_WRITABLE) != 0;
    if (!install_page(s->upage, new_page, writable)) {
      frame_free_page(new_page);
      return false;
    }
    s->kpage = new_page;
    s->flags = (s->flags & O_NON_PG_MASK) | O_PG_MEM;
    set_pinned(s->kpage, false);
  }
  return success;
}
#endif

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
