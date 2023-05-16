#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

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

/* END MODIFICATIONS */

#endif /* userprog/syscall.h */
