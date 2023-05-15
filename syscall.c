#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* MODIFICATIONS */

#include "threads/vaddr.h"

/* END MODIFICATIONS */

static void syscall_handler (struct intr_frame *);
 
/* MODIFICATIONS */

void get_args (struct intr_frame *f, int *arg, int num_of args);
void is_ptr_valid (const void* vaddr)

/* END MODIFICATIONS */

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}

/* MODIFICATIONS */

/* get_args: get arguments from the stack */
void get_args (struct intr_frame *f, int *args, int num_of args)
{
	int *ptr, i;
	
	for (i = 0; i < num_of_args; i++)
	{
		ptr = (int *) f->esp + i + 1;
		is_ptr_valid ((const void *) ptr);
		args[i] = *ptr;
	}
}

/* is_ptr_valid: checks the validity of the pointer */
void is_ptr_valid (const void *vaddr)
{
	if(vaddr < USER_VIR_ADDR_BOTTOM || !is_user_vaddr(vaddr))
	{
		// virtual memory address is not reserved for the user
		// TO BE ADDED LATER : system call exit
	}
}

/* END MODIFICATIONS*/
