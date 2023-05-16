#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/file.h"
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/* MODIFICATIONS */

struct thread* get_child(struct thread* t, int child_pid);
/**********************************/
struct open_file{
    int fd;
    struct file *file_ptr;
    struct list_elem open_files_elem;
};

/* END MODIFICATIONS */

#endif /* userprog/process.h */
