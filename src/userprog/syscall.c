#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "process.h"
#include "devices/input.h"
#include "userprog/pagedir.h"

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

/* End of system call functions */
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
	// printf("[SYS_CALL] ");	
	switch (syscall_number) {
		case SYS_HALT:
			// printf("HALT!\n");
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
			printf("OPEN\n");
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
		case SYS_TELL:
		case SYS_CLOSE:
			break;
		case SYS_MMAP:
		case SYS_MUNMAP:
			break;
		case SYS_CHDIR:
		case SYS_MKDIR:
		case SYS_READDIR:
		case SYS_ISDIR:
		case SYS_INUMBER:
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

/* Two conditions that terminate the process
 * 1. addr is not a valid user vaddr
 * 2. Virtual memory related
 */
void check_address(const void *addr) {
	if (!is_valid_user_vaddr(addr) || pagedir_get_page (thread_current() -> pagedir,addr) == NULL) {
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
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

int
wait (pid_t pid)
{
	process_wait(pid);
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
		printf("File write is not implemented yet\n");
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
		/* fprint has not been implemented yet! */
		printf("[ERROR] File read is not implemented yet\n");
		return -1;
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
	char *cmd_line_copy = palloc_get_page(0);
	if (cmd_line_copy == NULL) { exit(-1); }
	strlcpy(cmd_line_copy, cmd_line, PGSIZE);
	lock_acquire(&fs_lock);
	tid_t ret = process_execute(cmd_line_copy);
	lock_release(&fs_lock);
	if (ret == TID_ERROR) {
		return -1;
	}
	return ret;
}
