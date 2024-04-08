#ifndef FILESYS_FILE_H
#define FILESYS_FILE_H

#include "filesys/off_t.h"
#include <stdbool.h>

struct inode;

/* Opening and closing files. */
struct file *file_open (struct inode *);
struct file *file_reopen (struct file *);
void file_close (struct file *);
struct inode *file_get_inode (struct file *);
off_t file_get_pos (struct file *file);
void file_set_pos (struct file *file, off_t pos);

/* Reading and writing. */
off_t file_read (struct file *, void *, off_t);
off_t file_read_at (struct file *, void *, off_t size, off_t start);
off_t file_write (struct file *, const void *, off_t);
off_t file_write_at (struct file *, const void *, off_t size, off_t start);

/* Preventing writes. */
void file_deny_write (struct file *);
void file_allow_write (struct file *);

/* File position. */
void file_seek (struct file *, off_t);
off_t file_tell (struct file *);
off_t file_length (struct file *);

bool file_is_dir(struct file *file);

uint32_t *file_get_active_writers(struct file* file);
uint32_t *file_get_active_readers(struct file* file);
struct condition *file_get_write_cond(struct file* file);
struct condition *file_get_read_cond(struct file* file);
struct lock *file_get_monitor_lock(struct file* file);

#endif /* filesys/file.h */
