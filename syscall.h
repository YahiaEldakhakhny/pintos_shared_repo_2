#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
/* MODIFICATIONS */


/**
 * Acoording to Stanford documentation,
 * the code segment in PINTOS starts at the user virtual address 0x08048000
 * approx. 128 MB from the bottom of the address space
 */
#define USER_VIR_ADDR_BOTTOM ((void *)0x08048000)

/* END MODIFICATIONS */

void syscall_init (void);

/* MODIFICATIONS */

void halt(void);
void exit (int status);
int wait (int pid);
int exec (const char *cmd_line);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

struct file* get_file_by_fd(int target_fd);
/* END MODIFICATIONS */

#endif /* userprog/syscall.h */
