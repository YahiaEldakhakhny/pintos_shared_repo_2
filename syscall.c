#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* MODIFICATIONS */

#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

/*a lock to ensure multiple processes can't edit file at the same time*/
struct lock file_lock;

/* END MODIFICATIONS */

static void syscall_handler (struct intr_frame *);

/* MODIFICATIONS */

void get_args (struct intr_frame *f, int *arg, int num_of_args);
void is_ptr_valid (const void* vaddr);
int get_kernel_ptr (const void *user_ptr);

/* END MODIFICATIONS */

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /* MODIFICATIONS */
  
  /*printf ("system call!\n");
  thread_exit ();*/
  
  /* up to 3 stack args are needed */
  int args[3];
  
  /*Ensure provided ptr is valid*/
  is_ptr_valid((const void *)f->esp);
  
  /*Make system call coording to esp*/
  switch(*(int *) f->esp){
  	// HALT
  	case SYS_HALT:
  		halt();
  		break;
  	
  	// TERMINATE PROCESS
  	case SYS_EXIT:
  		get_args(f, &args[0], 1);
  		exit(args[0]);
  		break;
  	
  	//START ANOTHER PROCESS
  	case SYS_EXEC:
  		get_args(f, &args[0], 1);
  		
  		/*Transform arg from user vaddr. to kernel vaddr*/
  		args[0] = get_kernel_ptr ((const void *) args[0]);
  		f->eax = exec((const void *) args[0]);
  		break;
  	default:
  		exit(-1);
  		break;
  }
  
  /* END MODIFICATIONS */
}

/* MODIFICATIONS */

/* get_args: get arguments from the stack */
void get_args (struct intr_frame *f, int *args, int num_of_args)
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
void is_ptr_valid (const void* vaddr)
{
	if(vaddr < USER_VIR_ADDR_BOTTOM || !is_user_vaddr(vaddr))
	{
		thread_exit();
		// virtual memory address is not reserved for the user
		// TO BE ADDED LATER : system call exit
	}
}

/*convert user ptr to kernel ptr*/
int get_kernel_ptr (const void *user_ptr)
{
	is_ptr_valid(user_ptr);
	
	/*userptr -> kernelptr*/
	void *kernel_ptr = pagedir_get_page(thread_current()->pagedir, user_ptr);
	
	// Ensure kernel is not NULL
	if(kernel_ptr == NULL)
		exit(-1);
	return ((int) kernel_ptr);
}

/**
 * halt : system can't continue dueto hardware or software problem 
 * If halt occurs, system should shutdown not reboot
*/
void halt(void)
{
	shutdown_power_off();
}

/**
 * exit: Terminates the current userprog
 * @status: 0 in case success
 *         otherwise in case errors
 */
 void exit (int status)
 {
 	thread_current()->exit_status = status;
 	thread_exit();
 }
 
 /* wait */
 int wait (int pid)
 {
 	return process_wait(pid);
 }
 
 
 int exec (const char *cmd_line)
 {
 	struct thread* parent = thread_current();
 	
 	if(cmd_line == NULL)
 		return -1; // cannot run
 	
 	lock_acquire(&file_lock);
 	
 	/*create new process*/
 	int child_tid = process_execute(cmd_line);
 	struct thread* child = get_child(parent, child_tid);
 	if(!child->loaded)
 		child_tid = -1;
 	
 	lock_release(&file_lock);
 	return child_tid;
 	
 }
 
/* END MODIFICATIONS*/
