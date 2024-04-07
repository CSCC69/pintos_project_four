#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "filesys/free-map.h" 
#include "filesys/fsutil.h"

/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
    struct lock dir_lock;
  };

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };

static bool lookup (const struct dir *dir, const char *name, struct dir_entry *ep, off_t *ofsp);

bool dir_change(const char *dir) {
  struct dir *cur = dir_path_lookup(dir);
  if(cur == NULL){
    return false;
  }
  if(thread_current()->cwd != NULL)
    dir_close(thread_current()->cwd);
  thread_current()->cwd = cur;
  return true;
}

bool dir_make(const char *dir) {
  // printf("Thread %s starting dir_make\n", thread_current()->name);
  char *dir_copy = malloc(strlen(dir) + 1);
  strlcpy(dir_copy, dir, strlen(dir) + 1);

  char* last_slash = strrchr(dir_copy, '/');
  struct dir *cur;
  if(last_slash != NULL){
    *last_slash = '\0';
    cur = dir_path_lookup(dir_copy);
  } else{
    cur = thread_current()->cwd == NULL ? dir_open_root() : thread_current()->cwd;
  }

  lock_acquire(&cur->dir_lock);

  block_sector_t inode_sector = 0;
  bool success = (cur != NULL
                  && free_map_allocate (1, &inode_sector)
                  && dir_create(inode_sector)
                  && dir_add(cur, last_slash == NULL ? dir_copy : last_slash + sizeof(char), inode_sector));
  struct dir *new_dir = dir_open(inode_open(inode_sector));
  success = (success
             && dir_add(new_dir, ".", inode_sector)
             && dir_add(new_dir, "..", inode_get_inumber(cur->inode)));

  lock_release(&cur->dir_lock);

  if(new_dir != NULL)
    dir_close(new_dir);

  if(cur != thread_current()->cwd)
    dir_close(cur);

  return success;
}

struct dir *dir_path_lookup(char *dir_path) {
  // if (strrchr(dir_path, '/') == NULL){
  //   return thread_current()->cwd == NULL ? dir_open_root() : thread_current()->cwd;
  // }
  if (strcmp(dir_path, "") == 0){
    return thread_current()->cwd;
  }
  if (strcmp(dir_path, "/") == 0){
    return dir_open_root();
  }

  char *token, *save_ptr;

  struct dir *cur;

  if(dir_path[0] == '/') {
    // printf("root\n");
    cur = dir_open_root();
  } else{
    cur = thread_current()->cwd;
  }
 if (cur == NULL) {
  cur = dir_open_root();
 }

 if(strrchr(dir_path, '/') == NULL){
    struct dir_entry ep;
    off_t pos;
    if(!lookup(cur, dir_path, &ep, &pos)) {
      // printf("dir_path_lookup: lookup1 failed\n");
      return NULL;
    }
    struct dir *dir = dir_open(inode_open(ep.inode_sector));
    dir->pos = pos;
    if(cur != thread_current()->cwd)
      dir_close(cur);
    return dir;
  }
   

  for (token = strtok_r (dir_path, "/", &save_ptr); token != NULL; token = strtok_r (NULL, "/", &save_ptr)){
      struct dir_entry ep;
      off_t pos;
      if(!lookup(cur, token, &ep, &pos)) {
        // printf("dir_path_lookup: lookup2 failed\n");
        return NULL;
      }
      struct dir *dir = dir_open(inode_open(ep.inode_sector));
      dir->pos = pos;
      dir_close(cur);
      cur = dir;
  }
  return cur;
}

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector)
{
  return inode_create (sector, 0, true);
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      lock_init(&dir->dir_lock);
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  // printf("lookup: looking for %s\n", name);
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) {
        // printf("lookup: %s\n", e.name);
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
       }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode) 
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
  // printf("dir_add %s\n", name);
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  // printf("dir_remove %s\n", name);
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL || (inode_open_cnt(inode) > 1 && inode_is_dir(inode))){
    // printf("going to done %d %d %d %d\n", inode == NULL, inode_open_cnt(inode) > 1,inode_open_cnt(inode),  inode_is_dir(inode));
    goto done;}

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{}

bool fd_readdir(int fd, char *name){
  struct fd_file *fd_file = get_fd_file(thread_current(), fd);
  struct dir_entry e;

  while (inode_read_at (file_get_inode(fd_file->file), &e, sizeof e, file_get_pos(fd_file->file)) == sizeof e) 
    {
      file_set_pos(fd_file->file, sizeof e);
      if (e.in_use && strcmp(e.name, ".") != 0 && strcmp(e.name, "..") != 0)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        } 
    }
  return false;
}
