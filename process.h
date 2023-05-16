#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/thread.h"
struct child_process
{
    int pid;
    struct thread *t;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/* MODIFICATIONS */

struct thread* get_child(struct thread* t, tid_t child_tid UNUSED);

/* END MODIFICATIONS */

#endif /* userprog/process.h */
