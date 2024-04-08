#include "userprog/syscall.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "list.h"
#include "stdint.h"
#include "stdio.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "user/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <string.h>
#include <syscall-nr.h>
#include <userprog/pagedir.h>
#include <filesys/directory.h>
#include <filesys/inode.h>

void syscall_handler (struct intr_frame *);
void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
bool chdir (const char *dir);
bool mkdir (const char *dir);
bool readdir (int fd, char *name);
bool isdir (int fd);
int inumber (int fd);

static struct lock file_lock;

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a"(result) : "m"(*uaddr));
  return result;
}

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_lock);
}

/* Verifies that the stack pointer esp points to user memeory, and that 4 bytes
   can be dereferenced without page fault */
static void
verify_stack_pointer_word (void *esp)
{
  if (esp == NULL)
    exit (-1);
  if (!is_user_vaddr (esp))
    exit (-1);

  for (int i = 0; i < 4; i++)
    {
      if (get_user ((uint8_t *)(esp + i)) == -1)
        exit (-1);
    }
}

/* Saves the starting address of each of num_args argument on the stack,
 * starting at esp */
static void
stack_pop (void **syscall_args, int num_args, void *esp)
{
  for (int i = 0; i < num_args; i++)
    {
      verify_stack_pointer_word (esp);
      syscall_args[i] = esp;
      esp += 4;
    }
}

/* Verifies that a user-provided address is in user memory and can be
   dereferenced successfully without page fault */
static void
verify_user_pointer_word (char **esp)
{
  char *uaddr = *esp;
  if (!is_user_vaddr (uaddr))
    exit (-1);
  for (int i = 0; i < 4; i++)
    {
      if (get_user ((uint8_t *)(uaddr + i)) == -1)
        exit (-1);
    }
}

void
syscall_handler (struct intr_frame *f)
{
  void *esp = f->esp;

  verify_stack_pointer_word (esp);

  int syscall_number = *(int *)esp;
  esp += sizeof (int);

  void *syscall_args[3];

  switch (syscall_number)
    {
    // 0 args
    case SYS_HALT:
      halt ();
      break;
    // 1 arg
    case SYS_EXIT:
      stack_pop (&syscall_args[0], 1, esp);
      int status = *(int *)syscall_args[0];
      exit (status);
      break;
    case SYS_EXEC:
      stack_pop (&syscall_args[0], 1, esp);
      verify_user_pointer_word (syscall_args[0]);
      const char *file = *(const char **)syscall_args[0];
      f->eax = exec (file);
      break;
    case SYS_WAIT:
      stack_pop (&syscall_args[0], 1, esp);
      tid_t pid = *(tid_t *)syscall_args[0];
      f->eax = wait (pid);
      break;
    case SYS_REMOVE:
      stack_pop (&syscall_args[0], 1, esp);
      verify_user_pointer_word (syscall_args[0]);
      file = *(const char **)syscall_args[0];
      f->eax = remove (file);
      break;
    case SYS_OPEN:
      stack_pop (&syscall_args[0], 1, esp);
      verify_user_pointer_word (syscall_args[0]);
      file = *(const char **)syscall_args[0];
      f->eax = open (file);
      break;
    case SYS_FILESIZE:
      stack_pop (&syscall_args[0], 1, esp);
      int fd = *(int *)syscall_args[0];
      f->eax = filesize (fd);
      break;
    case SYS_TELL:
      stack_pop (&syscall_args[0], 1, esp);
      fd = *(int *)syscall_args[0];
      f->eax = tell (fd);
      break;
    case SYS_CLOSE:
      stack_pop (&syscall_args[0], 1, esp);
      fd = *(int *)syscall_args[0];
      close (fd);
      break;
    // 2 args
    case SYS_CREATE:
      stack_pop (&syscall_args[0], 2, esp);
      verify_user_pointer_word (syscall_args[0]);
      file = *(const char **)syscall_args[0];
      unsigned initial_size = *(unsigned *)syscall_args[1];
      f->eax = create (file, initial_size);
      break;
    case SYS_SEEK:
      stack_pop (&syscall_args[0], 2, esp);
      fd = *(int *)syscall_args[0];
      unsigned position = *(unsigned *)syscall_args[1];
      seek (fd, position);
      break;
    // 3 args
    case SYS_READ:
      stack_pop (&syscall_args[0], 3, esp);
      fd = *(int *)syscall_args[0];
      verify_user_pointer_word (syscall_args[1]);
      void *read_buffer = *(void **)syscall_args[1];
      unsigned size = *(unsigned *)syscall_args[2];
      f->eax = read (fd, read_buffer, size);
      break;
    case SYS_WRITE:
      stack_pop (&syscall_args[0], 3, esp);
      fd = *(int *)syscall_args[0];
      verify_user_pointer_word (syscall_args[1]);
      const char *write_buffer = *(const char **)syscall_args[1];
      unsigned int length = *(unsigned int *)syscall_args[2];
      f->eax = write (fd, write_buffer, length);
      break;
    case SYS_CHDIR:
      stack_pop (&syscall_args[0], 1, esp);
      verify_user_pointer_word (syscall_args[0]);
      const char *ch_dir = *(const char **)syscall_args[0];
      f->eax = chdir (ch_dir);
      break;
    case SYS_MKDIR:
      stack_pop (&syscall_args[0], 1, esp);
      verify_user_pointer_word (syscall_args[0]);
      const char *mk_dir = *(const char **)syscall_args[0];
      f->eax = mkdir (mk_dir);
      break;
    case SYS_READDIR:
      stack_pop (&syscall_args[0], 2, esp);
      fd = *(int *)syscall_args[0];
      verify_user_pointer_word (syscall_args[1]);
      char *name = *(char **)syscall_args[1];
      f->eax = readdir (fd, name);
      break;
    case SYS_ISDIR:
      stack_pop (&syscall_args[0], 1, esp);
      fd = *(int *)syscall_args[0];
      f->eax = isdir (fd);
      break;
    case SYS_INUMBER:
      stack_pop (&syscall_args[0], 1, esp);
      fd = *(int *)syscall_args[0];
      f->eax = inumber (fd);
      break;
    default:
      break;
    }
}

bool chdir (const char *dir){
  if(dir == NULL || strlen(dir) == 0)
    return false;
  return dir_change(dir);
}
bool mkdir (const char *dir){
  if(dir == NULL || strlen(dir) == 0)
    return false;
  return dir_make(dir);
}
bool readdir (int fd, char *name){
  return fd_readdir(fd, name);

}
bool isdir (int fd){
  return file_is_dir(get_fd_file(thread_current(), fd)->file);
}

int inumber (int fd){
  return inode_get_inumber(file_get_inode(get_fd_file(thread_current(), fd)->file));
}

/* Kernel implementation of the halt syscall */
void
halt (void)
{
  shutdown_power_off ();
}

/* Kernel implementation of the exit syscall*/
void
exit (int status)
{
  struct thread *cur = thread_current ();
  cur->exit_status = status;
  printf ("%s: exit(%d)\n", cur->name, status);
  thread_exit ();
}

/* Kernel implementation of the exec syscall*/
pid_t
exec (const char *cmd_line)
{
  if (cmd_line == NULL || strcmp (cmd_line, "") == 0)
    return PID_ERROR;

  int title_end = strcspn (cmd_line, " ");
  char *file_name = palloc_get_page (0);
  memcpy (file_name, cmd_line, title_end);
  file_name[title_end] = '\0';

  //lock_acquire (&file_lock);
  struct file *file = filesys_open (file_name);
  if (file == NULL)
    return -1;
  file_close (file);
  //lock_release (&file_lock);

  pid_t pid = process_execute (cmd_line);
  if (pid == PID_ERROR)
    return PID_ERROR;
  struct thread *thread = get_child_by_tid (pid);
  thread->cwd = thread_current()->cwd;
  sema_down (&thread->exec_sema);

  return pid;
}

/* Kernel implementation of the wait syscall */
int
wait (pid_t pid)
{
  if (pid < 0)
    return -1;
  return process_wait (pid);
}

/* Kernel implementation of the create syscall */
bool
create (const char *file, unsigned initial_size)
{
  if (file == NULL)
    exit (-1);
  if (strcmp (file, "") == 0 || strlen (file) > 14
      || strlen (file) == 0)
    return false;

  //lock_acquire (&file_lock);
  bool ret = filesys_create (file, initial_size);
  //lock_release (&file_lock);
  return ret;
}

/* Kernel implementation of the remove syscall */
bool
remove (const char *file)
{
  if (file == NULL || strcmp (file, "") == 0)
    exit (-1);
  //lock_acquire (&file_lock);
  bool success = filesys_remove (file);
  //lock_release (&file_lock);
  return success;
}

/* Kernel implementation of the open syscall */
int
open (const char *file)
{
  if (file == NULL || strcmp (file, "") == 0)
    return -1;
  //lock_acquire (&file_lock);
  struct file *opened_file = filesys_open (file);
  if (!opened_file)
    return -1;
  int fd = add_fd_file (thread_current (), opened_file);
  //lock_release (&file_lock);
  return fd;
}

/* Kernel implementation of the filesize syscall */
int
filesize (int fd)
{
  if (fd < 0)
    return -1;

  //lock_acquire (&file_lock);
  struct file *file = get_open_file (thread_current (), fd);
  if (!file)
    return -1;
  int file_size = file_length (file);
  //lock_release (&file_lock);
  return file_size;
}

/* Kernel implementation of the read syscall */
int
read (int fd, void *buffer, unsigned size)
{
  if (fd < 0)
    return -1;

  char *buf = (char *)buffer;
  if (fd == STDIN_FILENO)
    {
      for (unsigned i = 0; i < size; i++)
        buf[i] = input_getc ();
      return size;
    }
  else
    {
      struct file *file = get_open_file (thread_current (), fd);
      if (!file)
        return -1;

      struct lock *monitor_lock = file_get_monitor_lock(file);
      lock_acquire(monitor_lock);
      if (*file_get_active_writers(file) > 0)
        cond_wait(file_get_write_cond(file), monitor_lock);

      (*file_get_active_readers(file))++;
      off_t bytes_read = file_read (file, buffer, size);
      cond_signal(file_get_read_cond(file), monitor_lock);

      (*file_get_active_readers(file))--;
      lock_release(monitor_lock);
      return bytes_read;
    }
}

/* Kernel implementation of the write syscall */
int
write (int fd, const void *buffer, unsigned length)
{
  if (fd < 0 || buffer == NULL)
    return -1;

  if (fd == STDOUT_FILENO)
    {
      int remaining = length % 5;
      putbuf (buffer, remaining);

      for (unsigned i = remaining; i < length; i += 5)
        putbuf (&buffer[i], 5);

      return length;
    }
  else
    {
      struct file *file = get_open_file (thread_current (), fd);
      if (!file)
        return -1;

      struct lock *monitor_lock = file_get_monitor_lock(file);
      lock_acquire(monitor_lock);
      if (*file_get_active_readers(file) > 0)
        cond_wait(file_get_read_cond(file), monitor_lock);

      (*file_get_active_writers(file))++;
      off_t bytes_written = file_write (file, buffer, length);
      cond_signal(file_get_read_cond(file), monitor_lock);

      (*file_get_active_writers(file))--;
      lock_release(monitor_lock);
      return bytes_written;
    }
}

/* Kernel implementation of the seek syscall */
void
seek (int fd, unsigned position)
{
  if (fd < 0)
    return;

  struct file *file = get_open_file (thread_current (), fd);
  if (!file)
    return;
  file_seek (file, position);
}

/* Kernel implementation of the tell syscall */
unsigned
tell (int fd)
{
  if (fd < 0)
    return 0;

  struct file *file = get_open_file (thread_current (), fd);
  if (file)
    {
      //lock_acquire (&file_lock);
      off_t next_byte_from_start = file_tell (file);
      //lock_release (&file_lock);
      return next_byte_from_start;
    }
  return 0;
}

/* Kernel implementation of the close syscall */
void
close (int fd)
{
  if (fd < 0)
    return;

  struct file *file = get_open_file (thread_current (), fd);
  //lock_acquire (&file_lock);
  file_close (file);
  remove_fd_file (thread_current (), fd);
  //lock_release (&file_lock);
}
