#include "filesys/filesys.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include <debug.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  // printf("filesys_create: %s\n", name);
  block_sector_t inode_sector = 0;
  char *dir_copy = malloc (strlen (name) + 1);
  strlcpy (dir_copy, name, strlen (name) + 1);

  char *last_slash = strrchr (dir_copy, '/');
  struct dir *dir;

  if (last_slash != NULL)
    {
      *last_slash = '\0';
      // printf("looking up %s\n", dir_copy);
      dir = dir_path_lookup (dir_copy);
    }
  else
    {
      dir = thread_current ()->cwd == NULL ? dir_open_root ()
                                           : thread_current ()->cwd;
    }

  dir_lock_acquire (dir);

  bool success
      = (dir != NULL && free_map_allocate (1, &inode_sector)
         && inode_create (inode_sector, initial_size, false)
         && dir_add (dir,
                     last_slash == NULL ? name : last_slash + sizeof (char),
                     inode_sector));

  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);

  dir_lock_release (dir);

  if (dir != thread_current ()->cwd)
    dir_close (dir);

  // printf("filesys_create: %d\n", success);
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  // printf("filesys_open: %s\n", name);
  if (strcmp (name, "/") == 0)
    return file_open (inode_open (ROOT_DIR_SECTOR));

  char *dir_copy = malloc (strlen (name) + 1);
  strlcpy (dir_copy, name, strlen (name) + 1);

  char *last_slash = strrchr (dir_copy, '/');
  struct dir *dir;

  if (last_slash != NULL)
    {
      if (!strcmp (last_slash, dir_copy))
        dir = dir_open_root ();
      else
        {
          *last_slash = '\0';
          dir = dir_path_lookup (dir_copy);
        }
    }
  else
    dir = thread_current ()->cwd == NULL ? dir_open_root () : thread_current ()->cwd;

  struct inode *inode = NULL;

  if (dir != NULL)
    dir_lookup (dir, last_slash == NULL ? name : last_slash + sizeof (char), &inode);
  if (dir != thread_current ()->cwd)
    dir_close (dir);

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  // printf("filesys_remove: %s\n", name);

  char *dir_copy = malloc (strlen (name) + 1);
  strlcpy (dir_copy, name, strlen (name) + 1);

  char *last_slash = strrchr (dir_copy, '/');
  struct dir *cur;

  if (last_slash != NULL)
    {
      *last_slash = '\0';
      cur = dir_path_lookup (dir_copy);
    }
  else
    cur = thread_current ()->cwd == NULL ? dir_open_root () : thread_current ()->cwd;

  bool success
      = cur != NULL
        && dir_remove (cur,
                       last_slash == NULL ? name : last_slash + sizeof (char));

  if (cur != thread_current ()->cwd)
    dir_close (cur);

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
