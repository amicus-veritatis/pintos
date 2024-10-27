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
			printf("CREATE!\n");
			break;
		case SYS_REMOVE:
			printf("REMOVE!\n");
			break;
		case SYS_OPEN:
			f->eax = open((const char *) esp[1]);
			break;
		case SYS_FILESIZE:
			printf("FILESIZE\n");
			break;
		case SYS_READ:
			f->eax = read((int) esp[1], (void *) esp[2], (int) esp[3]);
			break;
		case SYS_WRITE:
			f->eax = write((int) esp[1], (const void *) esp[2], (int) esp[3]);
			break;
		case SYS_SEEK:
			printf("SEEK!\n");
			break;
		case SYS_TELL:
			printf("TELL!\n");
			break;
		case SYS_CLOSE:
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
	struct thread *t = thread_current();
	struct file *f = t->fd[fd_num];
	return f == NULL;
}

/* Two conditions that terminate the process
 * 1. addr is not a valid user vaddr
 * 2. Virtual memory related
 */
void check_address(const void *addr) {
	if (!is_valid_user_vaddr(addr) || pagedir_get_page (thread_current() -> pagedir,addr) == NULL) {
		exit(-1);
	} 
}

void check_fd_num (const int fd) {
	if (!is_valid_fd_num(fd)) {
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

int
open (const char* file_name)
{
	// Do not trust anything
	check_address(file_name);
	lock_acquire(&fs_lock);
	struct file *f = filesys_open(file_name);
	lock_release(&fs_lock);
	check_address(f);
	int cur_fd;
	for (cur_fd = STDERR_FILENO + 1; cur_fd < FD_MAX_SIZE; cur_fd++) {
		if (is_valid_fd_num) {
			break;
		}
	}
	check_fd_num(cur_fd);
	if (strcmp(thread_name(), file_name) == 0) {
		file_deny_write(f);
	}
	struct thread *t = thread_current();
	t->fd[cur_fd] = f;
	return cur_fd;
}
	
/* 
 * return with -1 if user is either trying to
 * write into stdin or cause out-of-range error
 */
int
write(int fd, const void *buffer, unsigned size)
{
	check_address(buffer);
	if (fd == STDIN_FILENO) {
		return -1;
	} else if (fd == STDOUT_FILENO) {
        	putbuf(buffer, size);
        	return size;	
	} 
	else if (fd > STDERR_FILENO && fd < FD_MAX_SIZE) {
		/* fprint has not been implemented yet! */
		printf("[ERROR] File write is not implemented yet\n");
		return -1;
	}
}
/* 
 * return with -1 if user is either trying to
 * read stdout  or cause out-of-range error
 * for input_getc(), see src/devices/input.h
 */
int read(int fd, void *buffer, unsigned size) {
	check_address(buffer);
	check_address(buffer+size);
	if (fd == STDOUT_FILENO) {
		return -1;
	} else if (fd == STDIN_FILENO) {
        	/* We do not check \0
		 * Trust programmers! */
		lock_acquire(&fs_lock);
		char *buf = buffer;
        	*buf = input_getc();
		lock_release(&fs_lock);
        	return size;	
	} 
	else if (fd > STDERR_FILENO && fd < FD_MAX_SIZE) {
		check_fd_num(fd);
		lock_acquire(&fs_lock);
		struct thread *t = thread_current();
		int f = file_read(t->fd[fd], buffer, size);
		lock_release(&fs_lock);
		return f;
	}
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
	if (cmd_line_copy == NULL) { exit(-1); }
	strlcpy(cmd_line_copy, cmd_line, PGSIZE);

	lock_acquire(&fs_lock);
	tid_t ret = process_execute(cmd_line_copy);
	lock_release(&fs_lock);

	palloc_free_page(cmd_line_copy);

	if (ret == TID_ERROR) {
		return -1;
	}

	return ret;
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


