#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "devices/block.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "stdio.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t start;                                 /* First data sector. */
    off_t length;                                         /* File size in bytes. */
    unsigned magic;                                       /* Magic number. */
    bool is_dir;                                          /* True if inode is a directory. */
    block_sector_t block_pointers[NUM_DIRECT_BLOCKS + 2]; /* Block pointers. */ 
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
//  if (pos >= inode->data.length) TODO: removed since this function is used for finding used and unused sectors
//    return -1;

  struct block *filesys = block_get_role(BLOCK_FILESYS);
  unsigned sector_idx = pos / BLOCK_SECTOR_SIZE;

  block_sector_t ret;

  if (sector_idx < NUM_DIRECT_BLOCKS){
    // printf("direct_block[%d] = %d\n", sector_idx, inode->data.block_pointers[sector_idx]);
    return inode->data.block_pointers[sector_idx];
  }
    
  sector_idx -= NUM_DIRECT_BLOCKS;

  if (sector_idx < NUM_INDIRECT_BLOCKS)
    {
      uint32_t indirect_block[BLOCK_POINTERS_PER_BLOCK];
      block_read(filesys, inode->data.block_pointers[INDIRECT_BLOCK], indirect_block);
      // printf("indirect_block[%d] = %d\n", sector_idx, indirect_block[sector_idx]);
      return indirect_block[sector_idx];
    }

  sector_idx -= NUM_INDIRECT_BLOCKS;
  uint32_t double_indirect_block[BLOCK_POINTERS_PER_BLOCK];
  block_read(filesys, inode->data.block_pointers[DOUBLE_INDIRECT_BLOCK], double_indirect_block);
  uint32_t indirect_block[BLOCK_POINTERS_PER_BLOCK];
  block_read(filesys, double_indirect_block[sector_idx / NUM_INDIRECT_BLOCKS], indirect_block);
  // printf("double_indirect_block[%d] = %d indirect_block[%d] = %d\n", sector_idx / NUM_INDIRECT_BLOCKS, double_indirect_block[sector_idx / NUM_INDIRECT_BLOCKS], sector_idx % BLOCK_POINTERS_PER_BLOCK, indirect_block[sector_idx % BLOCK_POINTERS_PER_BLOCK]);
  return indirect_block[sector_idx % BLOCK_POINTERS_PER_BLOCK];
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool is_dir)
{
  // printf("inode_create\n");
  struct inode_disk *disk_inode = NULL;

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode == NULL)
    return false;

  size_t sectors = bytes_to_sectors (length);
  disk_inode->length = length;
  disk_inode->is_dir = is_dir;
  disk_inode->magic = INODE_MAGIC;

  if (sectors > 0){
    static char zeros[BLOCK_SECTOR_SIZE];
    size_t i;

    for (i = 0; i < sectors && i < NUM_DIRECT_BLOCKS; i++) {
      free_map_allocate(1, &disk_inode->block_pointers[i]);
      block_write(fs_device, disk_inode->block_pointers[i], zeros);
    }

    if (sectors >= NUM_DIRECT_BLOCKS) {
      block_sector_t *indirect_block = calloc(1, sizeof(uint32_t) * BLOCK_POINTERS_PER_BLOCK);
      free_map_allocate(1, &disk_inode->block_pointers[INDIRECT_BLOCK]);
      
      for (; i < sectors && i - NUM_DIRECT_BLOCKS < NUM_INDIRECT_BLOCKS; i++) {
        free_map_allocate(1, &indirect_block[i - NUM_DIRECT_BLOCKS]);
        block_write(fs_device, indirect_block[i - NUM_DIRECT_BLOCKS], zeros);
      }

      block_write(fs_device, disk_inode->block_pointers[INDIRECT_BLOCK], indirect_block);
      free(indirect_block);
    }

    if (sectors >= NUM_DIRECT_BLOCKS + NUM_INDIRECT_BLOCKS) {
      block_sector_t *double_indirect_block = calloc(1, sizeof(uint32_t) * BLOCK_POINTERS_PER_BLOCK);
      free_map_allocate(1, &disk_inode->block_pointers[DOUBLE_INDIRECT_BLOCK]);
      
      for (size_t j = 0; j < (sectors - NUM_DIRECT_BLOCKS - NUM_INDIRECT_BLOCKS) / BLOCK_POINTERS_PER_BLOCK; j++) {
        block_sector_t *indirect_block = calloc(1, sizeof(uint32_t) * BLOCK_POINTERS_PER_BLOCK);
        free_map_allocate(1, &double_indirect_block[j]);
        
        for (; i < sectors && i - NUM_DIRECT_BLOCKS - NUM_INDIRECT_BLOCKS - j * BLOCK_POINTERS_PER_BLOCK < NUM_INDIRECT_BLOCKS; i++) {
          free_map_allocate(1, &indirect_block[i - NUM_DIRECT_BLOCKS - NUM_INDIRECT_BLOCKS - j * BLOCK_POINTERS_PER_BLOCK]);
          block_write(fs_device, indirect_block[i - NUM_DIRECT_BLOCKS - NUM_INDIRECT_BLOCKS - j * BLOCK_POINTERS_PER_BLOCK], zeros);
        }
        block_write(fs_device, double_indirect_block[j], indirect_block);
      }
      block_write(fs_device, disk_inode->block_pointers[DOUBLE_INDIRECT_BLOCK], double_indirect_block);
      free(double_indirect_block);
    }
  }
  
  block_write (fs_device, sector, disk_inode);

  free (disk_inode);
  return true;
}

// bool
// inode_create (block_sector_t sector, off_t length)
// {
//   struct inode_disk *disk_inode = NULL;
//   bool success = false;

//   ASSERT (length >= 0);

//   /* If this assertion fails, the inode structure is not exactly
//      one sector in size, and you should fix that. */
//   ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

//   disk_inode = calloc (1, sizeof *disk_inode);
//   if (disk_inode != NULL)
//     {
//       size_t sectors = bytes_to_sectors (length);
//       disk_inode->length = length;
//       disk_inode->magic = INODE_MAGIC;
//       if (free_map_allocate (sectors, &disk_inode->block_pointers)) 
//         {
//           block_write (fs_device, sector, disk_inode);
//           if (sectors > 0) 
//             {
//               static char zeros[BLOCK_SECTOR_SIZE];
//               size_t i;
              
//               for (i = 0; i < sectors; i++) 
//                 block_write (fs_device, disk_inode->block_pointers + i, zeros);
//             }
//           success = true; 
//         } 
//       free (disk_inode);
//     }
//   return success;
// }

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  // printf("inode_open\n");
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  // printf("inode_open %p\n", inode);
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  block_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  // printf("inode reopen %p\n", inode);
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  // printf("inode_close %p\n", inode);
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);

          size_t sectors = bytes_to_sectors (inode->data.length);

          for(int i = 0; i < sectors; i++){
            free_map_release(byte_to_sector(inode, i * BLOCK_SECTOR_SIZE), 1);
          }
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  // printf("inode_read_at size= %d\n", size);
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);


  // printf("bytes_read = %d, read %s\n", bytes_read, (char *) buffer);
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;
  // printf("inode_write_at offset = %d, size = %d\n", offset, size);

  if (inode->deny_write_cnt) {
    return 0;
  }
  if (bytes_to_sectors(offset+size) > bytes_to_sectors(inode->data.length))
    {
      if (!inode_grow(inode, size, offset)) {
        // printf("inode_grow failed\n");
        return 0;
      }
        
    } else {
      inode->data.length = offset + size > inode->data.length ? offset + size : inode->data.length;
      block_write (fs_device, inode->sector, &inode->data);
    }
    //PANIC("want to write to sector %d but file has %d sectors allocated, need to grow file by %d sectors", 
    //      bytes_to_sectors(offset), bytes_to_sectors(inode->data.length), bytes_to_sectors(offset - inode->data.length) + bytes_to_sectors(size));

  // printf("while start with offset %d\n", offset);
  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      // printf("sector_idx = %d\n", sector_idx);
      // printf("writing size %d to sector %d\n", size, sector_idx);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_write (fs_device, sector_idx, buffer + bytes_written);
          // void *read_buffer = malloc(BLOCK_SECTOR_SIZE);
          // block_read (fs_device, sector_idx, read_buffer + bytes_written);
          // printf("just wrote %s\n", (char *) read_buffer);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
      // printf("wrote %d bytes\n", bytes_written);
    }
  free (bounce);
  // if(bytes_written == 0)
  //   printf("bytes_written = %d inode->data.length = %d size = %d\n", bytes_written, inode->data.length, size);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

bool
inode_grow(struct inode *inode, off_t size, off_t offset)
{
  // printf("inode_grow\n");
  size_t allocated_sectors = bytes_to_sectors(inode->data.length);

  size_t sectors = bytes_to_sectors(offset + size);
  struct block *filesys = block_get_role(BLOCK_FILESYS);
  struct inode_disk *disk_inode = &inode->data;

  static char zeros[BLOCK_SECTOR_SIZE];
    size_t i;

  for (i = allocated_sectors; i < sectors && i < NUM_DIRECT_BLOCKS; i++) {
    free_map_allocate(1, &disk_inode->block_pointers[i]);
    block_write(fs_device, disk_inode->block_pointers[i], zeros);
  }
  //TODO: 0 check is sus since 0 is a valid sector
  //TODO: if the indirect or double indirect blocks are already initialized (so we don't calloc them) we should read the
  //TODO: fix the compiler errors and warnings no clue how this passes more tests
  if (sectors >= NUM_DIRECT_BLOCKS) {
    block_sector_t *indirect_block = calloc(1, sizeof(uint32_t) * BLOCK_POINTERS_PER_BLOCK);
    if(disk_inode->block_pointers[INDIRECT_BLOCK] == 0){
      free_map_allocate(1, &disk_inode->block_pointers[INDIRECT_BLOCK]);
    } else {
      block_read(fs_device, disk_inode->block_pointers[INDIRECT_BLOCK], indirect_block);
    }
    
    for (; i < sectors && i - NUM_DIRECT_BLOCKS < NUM_INDIRECT_BLOCKS; i++) {
      free_map_allocate(1, &indirect_block[i - NUM_DIRECT_BLOCKS]);
      block_write(fs_device, indirect_block[i - NUM_DIRECT_BLOCKS], zeros);
    }

    block_write(fs_device, disk_inode->block_pointers[INDIRECT_BLOCK], indirect_block);
    free(indirect_block);
  }

  if (sectors >= NUM_DIRECT_BLOCKS + NUM_INDIRECT_BLOCKS) {
    // printf("Growing double indirect\n");
    block_sector_t *double_indirect_block = calloc(1, sizeof(uint32_t) * BLOCK_POINTERS_PER_BLOCK);
    if(disk_inode->block_pointers[DOUBLE_INDIRECT_BLOCK] == 0) {
      free_map_allocate(1, &disk_inode->block_pointers[DOUBLE_INDIRECT_BLOCK]);
    } else {
      block_read(fs_device, disk_inode->block_pointers[DOUBLE_INDIRECT_BLOCK], double_indirect_block);
    }

    for (size_t j = 0; j <= (sectors - NUM_DIRECT_BLOCKS - NUM_INDIRECT_BLOCKS) / BLOCK_POINTERS_PER_BLOCK; j++) {
      block_sector_t *indirect_block = calloc(1, sizeof(uint32_t) * BLOCK_POINTERS_PER_BLOCK);
      if(double_indirect_block[j] == 0) {
        free_map_allocate(1, &double_indirect_block[j]);
      } else {
        block_read(fs_device, double_indirect_block[j], indirect_block);
      }
      
      for (; i < sectors && i - NUM_DIRECT_BLOCKS - NUM_INDIRECT_BLOCKS - j * BLOCK_POINTERS_PER_BLOCK < NUM_INDIRECT_BLOCKS; i++) {
        free_map_allocate(1, &indirect_block[i - NUM_DIRECT_BLOCKS - NUM_INDIRECT_BLOCKS - j * BLOCK_POINTERS_PER_BLOCK]);
        block_write(fs_device, indirect_block[i - NUM_DIRECT_BLOCKS - NUM_INDIRECT_BLOCKS - j * BLOCK_POINTERS_PER_BLOCK], zeros);
        // printf("Grew double_indirect_block[%d] = %d indiect_block[%d] = %d", j, double_indirect_block[j], i - NUM_DIRECT_BLOCKS - NUM_INDIRECT_BLOCKS - j * BLOCK_POINTERS_PER_BLOCK, indirect_block[i - NUM_DIRECT_BLOCKS - NUM_INDIRECT_BLOCKS - j * BLOCK_POINTERS_PER_BLOCK]);
      }

      block_write(fs_device, double_indirect_block[j], indirect_block);
      free(indirect_block);
    }
    block_write(fs_device, disk_inode->block_pointers[DOUBLE_INDIRECT_BLOCK], double_indirect_block);
    free(double_indirect_block);
  }

  inode->data.length = offset + size > inode->data.length ? offset + size : inode->data.length;
  block_write (fs_device, inode->sector, &inode->data);
  return true;

  //PANIC("allocated_sectors: %d, zero_sectors: %d, data_sectors: %d", allocated_sectors, zero_sectors, data_sectors);
}

bool inode_is_dir(struct inode *inode){
  return inode->data.is_dir;
}

int inode_open_cnt(struct inode *inode){
  return inode->open_cnt;
}
