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
  //Mod
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f) 
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
  	/**MODIFICATIONS
	case SYS_CREATE:
        f->eax = create ((char *) *(esp + 1), *(esp + 2));
        break;
    case SYS_REMOVE:
        f->eax = remove ((char *) *(esp + 1));
        break;
    case SYS_OPEN:
        f->eax = open ((char *) *(esp + 1));
        break;
    case SYS_FILESIZE:
	    f->eax = filesize (*(esp + 1));
	    break;
    case SYS_READ:
        f->eax = read (*(esp + 1), (void *) *(esp + 2), *(esp + 3));
        break;
    case SYS_WRITE:
        f->eax = write (*(esp + 1), (void *) *(esp + 2), *(esp + 3));
        break;
    case SYS_SEEK:
        seek (*(esp + 1), *(esp + 2));
        break;
    case SYS_TELL:
        f->eax = tell (*(esp + 1));
        break;
    case SYS_CLOSE:
        close (*(esp + 1));
        break;
		*/
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
	struct thread *t=thread_current();
 	t->exit_status = status;
	//closing opened files
	if(&(t->open_files_list) != NULL)
	{
		struct open_file *of;
		for (struct list_elem *e = &(t->open_files_list).head.next; e != &(t->open_files_list).tail; e = e->next)
  		{
			of=list_entry(e,struct open_file,open_files_elem);
			close(of->fd);
  		}
	}
	//check if there are any child processes running and wait on them
	if(&(t->children_list) != NULL)
	{
		struct thread *cp;
		for (struct list_elem *e = &(t->children_list).head.next; e != &(t->children_list).tail; e = e->next)
  		{
			cp=list_entry(e,struct thread, child_elem);
			wait(cp->pid);
  		}
	}
	//check if the child process is blocking the parent 
	if(t->parent_thread->waiting_on==t->pid)
	{
		sema_up(&t->sem_wait_on_child);
	}
 	thread_exit();
 }
 
 /* wait */
 int wait (int pid)
 {
 /* MODIFICATIONS */

  struct thread *parent = thread_current(); /* current process */
  struct thread *child = NULL;              /* Child process */

  /* Ensure there is child process needed to wait for */
  if (list_empty(&parent->children_list))
    return -1;

  /* Search parent list of children for child_tid */
  child = get_child(parent, pid);

  /* If child not found, return -1 */
  if (child == NULL)
    return -1;

  /* Remove child for which we are waiting from the list*/
  list_remove(&child->child_elem);

  /* Make parent wait till child finishes executing */
  parent->waiting_on = child->pid;
  sema_down(&(child->sem_wait_on_child));

  /* Return exit status of child when terminated*/
  return (child->exit_status);

  /* END MODIFICATIONS */
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
 	lock_release(&file_lock);
 	return child_tid;
 }
 
 void close (int fd)
 {
	struct open_file *of; 
	struct thread * t=thread_current();
	for (struct list_elem *e = &(t->open_files_list).head.next; e != &(t->open_files_list).tail; e = e->next)
  	{
		of=list_entry(e,struct open_file, open_files_elem);
		if (of->fd == fd)
		{
			file_close(of->file_ptr);
			lock_release(&file_lock);
			return;
		}
  	}
 }
 
 /**MODIFICATIONS*/
int
open (const char *file_name)
{
  struct open_file *of; 
  struct thread *t = thread_current();
  // Maybe check if file_name is a valid pointer...?
  lock_acquire(&file_lock);
  of->file_ptr = filesys_open (file_name); // this function takes a file name and returns struct file (see filesys.c)
  if (of != NULL)
    {
		(t->fd_last)++;
		(of->fd) = (t->fd_last);
		list_push_back (&(t->open_files_list), &(of->open_files_elem));
    }
	else
	{
		lock_release(&file_lock); 
	}
  return (of->fd);
}
 
int
filesize (int fd)
{
	struct open_file *of; 
	struct thread *t = thread_current();
	int file_size = -1;
	//lock_acquire();
	for (struct list_elem *e = &(t->open_files_list).head.next; e != &(t->open_files_list).tail; e = e->next)
  	{
		of=list_entry(e,struct open_file, open_files_elem);
		if (of->fd == fd)
		{
			file_size = file_length (of->file_ptr);
		}
  	}
	//lock_release();
	return file_size;
}

bool
create (const char *file_name, unsigned size)
{
  bool is_file_creation_successful;
  // Maybe check if file_name is a valid pointer...?
  //lock_acquire();
  is_file_creation_successful = filesys_create(file_name, size); //(see filesys.c)
  //lock_release();
  return is_file_creation_successful;
}

bool 
remove (const char *file_name)
{
  bool is_file_creation_successful;
  // Maybe check if file_name is a valid pointer...?
  //lock_acquire();
  is_file_creation_successful = filesys_remove(file_name); //(see filesys.c)
  //lock_release();
  return is_file_creation_successful;
}

void 
seek (int fd, unsigned position)
{
  struct open_file *of; 
  struct thread *t = thread_current();
  //lock_acquire();
  for (struct list_elem *e = &(t->open_files_list).head.next; e != &(t->open_files_list).tail; e = e->next)
  	{
		of=list_entry(e,struct open_file, open_files_elem);
		if (of->fd == fd)
		{
			file_seek(of->file_ptr, position); // see file.c
		}
  	}
  //lock_release();
}

unsigned 
tell (int fd)
{
  struct open_file *of; 
  struct thread *t = thread_current();
  int position_in_file = 0;
  //lock_acquire();
  for (struct list_elem *e = &(t->open_files_list).head.next; e != &(t->open_files_list).tail; e = e->next)
  	{
		of=list_entry(e,struct open_file, open_files_elem);
		if (of->fd == fd)
		{
			position_in_file = file_tell(of->file_ptr); // see file.c
		}
  	}
  //lock_release();
  return position_in_file;
}

int 
read (int fd, void *buffer, unsigned length)
{
	return 0;
}

int 
write (int fd, const void *buffer, unsigned length)
{
	return 0;
}
/***/

/* END MODIFICATIONS*/
