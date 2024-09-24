#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

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
/* End of system call functions */

struct lock fs_lock;

void
syscall_init (void) 
{
	lock_init(&fs_lock);
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
	uint32_t* esp = (uint32_t*) f->esp;
	int syscall_number = *esp;
	// printf("[SYS_CALL] ");
	switch (syscall_number) {
		case SYS_HALT:
			// printf("HALT!\n");
			break;
		case SYS_EXIT:
			// printf("EXIT!\n");
			// printf("(int) esp[1]: %d\n", (int) esp[1]);
			exit((int) esp[1]);
			break;
		case SYS_EXEC:
			printf("EXEC!\n");
			break;
		case SYS_WAIT:
			printf("WAIT!\n");
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
			printf("몰라 씨발련아!!~!~!!!!!!!\n");
			break;
		case SYS_MMAP:
		case SYS_MUNMAP:
			printf("PROJECT 3!\n");
			break;
		case SYS_CHDIR:
		case SYS_MKDIR:
		case SYS_READDIR:
		case SYS_ISDIR:
		case SYS_INUMBER:
			printf("PROJECT 4!\n");
			break;
		default:
			printf("하다리, %d\n", *esp);
			break;
	}
}		


static bool
is_valid_user_vaddr (const void* addr){
	return addr != NULL && is_user_vaddr(addr);
}


void check_address(const void *addr) {
	if (!is_valid_user_vaddr(addr)) {
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
	printf("%s: exit(%d)\n", cur->name, status);
	// cur -> exit_status = status;
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
        	lock_acquire(&fs_lock);
        	putbuf(buffer, size);
        	lock_release(&fs_lock);
        	return size;	
	} 
	// printf("File write not implemented yet.\n");
	return -1;
}
/* 
 * return with -1 if user is either trying to
 * read stdout  or cause out-of-range error
 */
int read(int fd, void *buffer, unsigned size) {
	check_address(buffer);

	if (fd == STDOUT_FILENO) {
		return -1;
	} else if (fd == STDIN_FILENO) {
        	lock_acquire(&fs_lock);
        	int size = input_getc();
        	lock_release(&fs_lock);
        	return size;	
	} 
	printf("File write not implemented yet.\n");
	return -1;
}
