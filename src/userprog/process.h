#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

/* The arguments for a process */
struct prog_args
{
  char *name;    /* The executable's name */
  char **args;   /* The executable's arguments */
  int arg_count; /* The number of arguments */
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

void free_thread_and_childs (struct thread *parent);
void free_childs (struct thread *parent);

#endif /* userprog/process.h */
