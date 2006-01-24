/*
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.80.1 Date: Tue Jan 24 13:51:25 NZDT 2006$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************
*/
/*
 * sgzip compressed loop driver. Based on the cloop driver.
 * The sgzip format is very similar to the cloop format with 2 major exceptions:
 *   - The index in cloop is at the begining of the file, while sgzip places the index at the end.
 *   - The sgzip format has redundancy built in with block offsets stored interleaved between 
 *      the compressed blocks leading to a possibility of reconstructing the index if the file is 
 *      truncated.
 *
 *   In practice this means that there is no need to store the file in
 *   memory while building it, since the index is written at the end,
 *   only the index needs to be stored. This means that you do not
 *   need to have massive amount of swap like you do when using cloop.
 *
 * Note that for now sgloop uses major number 241 so it may coexists with cloop.
 *
 * ------- Following is the documentation for the original cloop modules.
 *
 *  compressed_loop.c: Read-only compressed loop blockdevice
 *  hacked up by Rusty in 1999, extended and maintained by Klaus Knopper
 *
 *  cloop file looks like:
 *  [32-bit uncompressed block size: network order]
 *  [32-bit number of blocks (n_blocks): network order]
 *  [64-bit file offsets of start of blocks: network order]
 *    * (n_blocks + 1).
 * n_blocks of:
 *   [compressed block]
 *
 *  Inspired by loop.c by Theodore Ts'o, 3/29/93.
 *
 * Copyright 1999-2003 by Paul `Rusty' Russell & Klaus Knopper.
 * Redistribution of this file is permitted under the GNU Public License.
 *
 * CHANGES: (see CHANGELOG file)
 */

#define CLOOP_NAME "sgloop"
#define CLOOP_VERSION "0.01"
#define CLOOP_MAX 8

/* Define this if you are using Greenshoe Linux */
/* #define REDHAT_KERNEL */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/devfs_fs_kernel.h>
#include <asm/semaphore.h>
#include <asm/div64.h> /* do_div() for 64bit division */
#include <asm/uaccess.h>
/* Use zlib_inflate from lib/zlib_inflate */
#include <linux/zutil.h>
#include <linux/loop.h>
// #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
// #include <linux/buffer_head.h>
// #endif
#include "sgloop.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
EXPORT_NO_SYMBOLS;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,9)
/* New License scheme */
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif
#endif

#ifndef MIN
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#endif

#ifndef MAX
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#endif

/* Use experimental major for now */
#define MAJOR_NR 241

#define DEVICE_NAME CLOOP_NAME
#define DEVICE_NR(device) (MINOR(device))
#define DEVICE_ON(device)
#define DEVICE_OFF(device)
#define DEVICE_NO_RANDOM
#define TIMEOUT_VALUE (6 * HZ)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
#include <linux/blk.h>
#else
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#endif

#if 0
#define DEBUGP printk
#else
#define DEBUGP(format, x...)
#endif

/* One file can be opened at module insertion time */
/* insmod cloop file=/path/to/file */
static char *file=NULL;
MODULE_PARM(file, "s");
MODULE_PARM_DESC(file, "Initial sgzip image file (full path) for /dev/cloop");
static struct file *initial_file=NULL;

struct cloop_device
{
 /* Copied straight from the file */
 struct cloop_head head;
  
 /* An array of offsets of compressed blocks within the file */
 loff_t *offsets;

 /* We buffer one uncompressed `block' */
 int buffered_blocknum;
 void *buffer;
 void *compressed_buffer;

 z_stream zstream;

 struct file   *backing_file;  /* associated file */
 struct inode  *backing_inode; /* for bmap */

 unsigned int underlying_blksize;
 int refcnt;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
 int dev;
#else
 struct block_device *bdev;
#endif
 int isblkdev;
 struct semaphore clo_lock;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
 struct gendisk *disk;
 request_queue_t *clo_queue;
#endif
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
static int cloop_sizes[CLOOP_MAX];
static int cloop_blksizes[CLOOP_MAX];
#endif

static struct cloop_device cloop_dev[CLOOP_MAX];
static char *cloop_name=CLOOP_NAME;
static const int max_cloop = CLOOP_MAX;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
static devfs_handle_t devfs_handle;
#endif

#if (!(defined(CONFIG_ZLIB_INFLATE) || defined(CONFIG_ZLIB_INFLATE_MODULE))) /* Must be compiled into kernel. */
#error  "Invalid Kernel configuration. CONFIG_ZLIB_INFLATE support is needed for cloop."
#endif

static int uncompress(struct cloop_device *clo, char *dest, unsigned long *destLen,
                      char *source, unsigned long sourceLen)
{
 /* Most of this code can be found in fs/cramfs/uncompress.c */
 int err;
 clo->zstream.next_in = source;
 clo->zstream.avail_in = sourceLen;
 clo->zstream.next_out = dest;
 clo->zstream.avail_out = *destLen;
 err = zlib_inflateReset(&clo->zstream);
 if (err != Z_OK)
  {
   printk(KERN_ERR "%s: zlib_inflateReset error %d\n", cloop_name, err);
   zlib_inflateEnd(&clo->zstream); zlib_inflateInit(&clo->zstream);
  }
 err = zlib_inflate(&clo->zstream, Z_FINISH);
 *destLen = clo->zstream.total_out;
 if (err != Z_STREAM_END) return err;
 return Z_OK;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
/* Get blocksize of underlying device */
static unsigned int get_blksize(int dev)
{
 unsigned int bs = BLOCK_SIZE;
 if (blksize_size[MAJOR(dev)])
  {
    bs = blksize_size[MAJOR(dev)][MINOR(dev)];
    if (!bs) bs = BLOCK_SIZE;
  }
 return bs;
}
#endif

/* This is more complicated than it looks. */
struct clo_read_data
{
 struct cloop_device *clo;
 char *data; /* We need to keep track of where we are in the buffer */
 int bsize;
};

/* We need this for do_generic_file_read() because the default function */
/* wants to read into user-space for an unknown reason. :-/ See loop.c. */
static int clo_read_actor(read_descriptor_t * desc, struct page *page,
                          unsigned long offset, unsigned long size)
{
 char *kaddr;
 struct clo_read_data *p = (struct clo_read_data*)desc->buf;
 unsigned long count = desc->count;
 if (size > count) size = count;
 kaddr = kmap(page);
 memcpy(p->data, kaddr + offset, size);
 kunmap(page);
 desc->count = count - size;
 desc->written += size;
 p->data += size;
 return size;
}

static size_t clo_read_from_file(struct cloop_device *clo, struct file *f, char *buf,
  loff_t pos, size_t buf_len)
{
 size_t buf_done=0;
 while (buf_done < buf_len)
  {
   size_t size = buf_len - buf_done;
   struct clo_read_data cd={ /* do_generic_file_read() needs this. */
           clo,              /* struct cloop_device *clo */
           (char *)(buf + buf_done), /* char *data */
           size};            /* Actual data size */
   read_descriptor_t desc;
   desc.written = 0;
   desc.count   = size;
   desc.buf     = (char*)&cd;
   desc.error   = 0;
#ifdef REDHAT_KERNEL /* Greenshoe Linux */
   do_generic_file_read(f, &pos, &desc, clo_read_actor, 0);
#else /* Normal Kernel */
   do_generic_file_read(f, &pos, &desc, clo_read_actor);
#endif
   if(desc.error||desc.written<=0)
    {
     int left = size - desc.written;
     if(left<0) left = 0; /* better safe than sorry */
     printk(KERN_ERR "%s: Read error at pos %Lu in file %s, %d bytes lost.\n",
            cloop_name, pos, file, left);
     memset(buf + buf_len - left, 0, left);
     break;
    }
   buf_done+=desc.written;
  }
 return buf_done;
}

/* This looks more complicated than it is */
static int load_buffer(struct cloop_device *clo, int blocknum)
{
 unsigned int buf_done = 0;
 unsigned long buflen;
 unsigned int buf_length;
 int ret;

 if(blocknum > (clo->head.x.num_blocks) || blocknum < 0)
  {
   printk(KERN_WARNING "%s: Invalid block number %d requested.\n",
                       cloop_name, blocknum);
   clo->buffered_blocknum = -1;
   return 0;
  }

 if (blocknum == clo->buffered_blocknum) return 1;

 /* Is there a ntohl for 64-bit values? */
 buf_length = (clo->offsets[blocknum+1]) - (clo->offsets[blocknum]);

/* Load one compressed block from the file. */
 DEBUGP("seeking to %llu[%u] -> %llu size %u\n",clo->offsets[blocknum],blocknum,(clo->offsets[blocknum] + sizeof(struct cloop_head) + sizeof(unsigned int)*(blocknum+1)),buf_length);

 clo_read_from_file(clo, clo->backing_file, (char *)clo->compressed_buffer,
                    (clo->offsets[blocknum] + sizeof(struct cloop_head) + sizeof(unsigned int)*(blocknum+1)), buf_length);

 /* Do decompression into real buffer. */
 buflen = (clo->head.block_size);

 /* Do the uncompression */
 ret = uncompress(clo, clo->buffer, &buflen, clo->compressed_buffer,
                  buf_length);

 /* DEBUGP("cloop: buflen after uncompress: %ld\n",buflen); */

 if (ret != 0)
  {
   printk(KERN_ERR "%s: error %i uncompressing block %u %u/%lu/%u/%u "
          "%Lu-%Lu\n", cloop_name, ret, blocknum,
	  (clo->head.block_size), buflen, buf_length, buf_done,
	  (clo->offsets[blocknum]), (clo->offsets[blocknum+1]));
   clo->buffered_blocknum = -1;
   return 0;
  }
 clo->buffered_blocknum = blocknum;
 return 1;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
static int make_clo_request(request_queue_t *q, int rw, struct buffer_head *bh)
#else
static int make_clo_request(request_queue_t *q, struct bio *bio)
#endif
{
 struct cloop_device *cloop;
 int status = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
 int cloop_num;
#endif
 unsigned int len;
 loff_t offset;
 char *dest;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
 /* (possible) high memory conversion */
 bh = blk_queue_bounce(q,rw,bh);
#else
 int rw = bio_rw(bio);
 unsigned int vecnr;
 cloop = q->queuedata;
#endif

 /* quick sanity checks */
 if (rw != READ && rw != READA)
  {
   DEBUGP("do_clo_request: bad command\n");
   goto out;
  }

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
 cloop_num = MINOR(bh->b_rdev);

 if (cloop_num >= max_cloop)
  {
   DEBUGP("do_clo_request: invalid cloop minor\n");
   goto out;
  }

 cloop = &cloop_dev[cloop_num];
#endif

 if (!cloop->backing_file)
  {
   DEBUGP("do_clo_request: not connected to a file\n");
   goto out;
  }

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
 if (bh->b_rsector == -1)
  {
   DEBUGP("do_clo_request: bad sector requested\n");
   goto out;
  }

 down(&cloop->clo_lock);
 len        = bh->b_size;
 offset     = (loff_t)bh->b_rsector << 9;
 dest       = bh->b_data;
#else
 down(&cloop->clo_lock);
 offset     = (loff_t)bio->bi_sector << 9;
 for(vecnr=0; vecnr < bio->bi_vcnt; vecnr++)
  {
   struct bio_vec *bvec=&bio->bi_io_vec[vecnr];
   len = bvec->bv_len;
   dest= kmap(bvec->bv_page) + bvec->bv_offset;
#endif

  
 while(len > 0)
  {
   u_int32_t length_in_buffer;
   loff_t block_offset=offset;
  
   /* do_div (div64.h) returns the 64bit division remainder and  */
   /* puts the result in the first argument, i.e. block_offset   */
   /* becomes the blocknumber to load, and offset_in_buffer the  */
   /* position in the buffer */
   u_int32_t offset_in_buffer;
   offset_in_buffer = do_div(block_offset, (cloop->head.block_size));
 
   status=load_buffer(cloop,block_offset);
   if(!status) break; /* invalid data, leave inner loop, goto next request */
  
   /* Now, at least part of what we want will be in the buffer. */
   length_in_buffer = (cloop->head.block_size) - offset_in_buffer;
  
   if(length_in_buffer > len)
    {
/*     DEBUGP("Warning: length_in_buffer=%u > len=%u\n",
                        length_in_buffer,len); */
     length_in_buffer = len;
    }

   memcpy(dest, cloop->buffer + offset_in_buffer, length_in_buffer);

   dest   += length_in_buffer;
   len    -= length_in_buffer;
   offset += length_in_buffer;
  } /* while inner loop */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
   kunmap(bvec->bv_page);
  } /* end for vecnr*/
#endif

 up(&cloop->clo_lock);

out:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
 bh->b_end_io(bh,status);
#else
 bio_endio(bio, bio->bi_size,status==0);
#endif
 return 0;
}

/* Read header and offsets from already opened file */
static int clo_set_file(int cloop_num, struct file *file, char *filename)
{
 struct cloop_device *clo=&cloop_dev[cloop_num];
 struct inode *inode;
 char *bbuf=NULL;
 unsigned int i, offsets_read, total_offsets=0;
 unsigned long largest_block=0;
 int isblkdev;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
 int dev;
#endif
 int error = 0;

 inode = file->f_dentry->d_inode;
 isblkdev=S_ISBLK(inode->i_mode)?1:0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
 dev=isblkdev?inode->i_rdev:inode->i_dev;
#endif
 if(!isblkdev&&!S_ISREG(inode->i_mode))
  {
   printk(KERN_ERR "%s: %s not a regular file or block device\n",
		   cloop_name, filename);
   error=-EBADF; goto error_release;
  }

 clo->backing_file = file;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
 clo->dev = dev;
#endif
 clo->backing_inode= inode ;

 if(!isblkdev&&inode->i_size<sizeof(struct cloop_head))
  {
   printk(KERN_ERR "%s: %lu bytes (must be >= %u bytes)\n",
                   cloop_name, (unsigned long)inode->i_size,
		   (unsigned)sizeof(struct cloop_head));
   error=-EBADF; goto error_release;
  }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
 if(isblkdev)
  {
   request_queue_t *q = bdev_get_queue(inode->i_bdev);
   blk_queue_max_sectors(clo->clo_queue, q->max_sectors);
   blk_queue_max_phys_segments(clo->clo_queue,q->max_phys_segments);
   blk_queue_max_hw_segments(clo->clo_queue, q->max_hw_segments);
   blk_queue_max_segment_size(clo->clo_queue, q->max_segment_size);
   blk_queue_segment_boundary(clo->clo_queue, q->seg_boundary_mask);
   blk_queue_merge_bvec(clo->clo_queue, q->merge_bvec_fn);
   clo->underlying_blksize = block_size(inode->i_bdev);
 }
else
   clo->underlying_blksize = inode->i_blksize;
#else
 /* Get initial block size out of device */
 clo->underlying_blksize = get_blksize(dev);
#endif
 DEBUGP("Underlying blocksize is %u\n", clo->underlying_blksize);

 //Read the header:
 if(clo_read_from_file(clo,file,(char *)&clo->head,0,sizeof(clo->head))<sizeof(clo->head)) {
   printk(KERN_ERR "%s: unable to read file header\n",
	  cloop_name);
   error=-EBADF; goto error_release;
 };

 if(strncmp(SGZ_MAGIC,clo->head.magic,sizeof(SGZ_MAGIC))) {
   printk(KERN_ERR "%s: This is not a valid sgzip file\n",
	  cloop_name);
   error=-EBADF; goto error_release;
 };

 bbuf = vmalloc(clo->underlying_blksize);
 if(!bbuf)
   {
     printk(KERN_ERR "%s: out of kernel mem for block buffer (%lu bytes)\n",
	    cloop_name, (unsigned long)clo->underlying_blksize);
     error=-ENOMEM; goto error_release;
   }

 /* Read the last 6 chars of the file into our buffer:*/
 clo_read_from_file(clo,file,bbuf,inode->i_size-strlen(INDEX_MAGIC)-4,strlen(INDEX_MAGIC)+4);

 if(!strncmp(INDEX_MAGIC,bbuf+4,strlen(INDEX_MAGIC))) {
   size_t bytes_read;

   total_offsets=(*(unsigned int *)bbuf);
   DEBUGP("Found Index. Number of blocks is %u\n",total_offsets);

   clo->offsets = vmalloc(sizeof(loff_t) * total_offsets);
   if (!clo->offsets)
     {
       printk(KERN_ERR "%s: out of kernel mem for offsets\n", cloop_name);
       error=-ENOMEM; goto error_release;
     };
   
   clo->offsets[0]=0;

   bytes_read = clo_read_from_file(clo, file, (char *)(clo->offsets+1),
                                  inode->i_size - strlen(INDEX_MAGIC) - 4 - total_offsets*sizeof(*clo->offsets), total_offsets*sizeof(*clo->offsets));
   if(bytes_read<total_offsets*sizeof(*clo->offsets)) {
     printk(KERN_ERR "%s: could not read the required number of offsets (%u)\n", cloop_name, total_offsets);
     error=-EBADF; goto error_release_free;
   };

   clo->head.x.num_blocks=total_offsets;

   for(i=0;i<total_offsets;i++) 
     DEBUGP("offset %u is at %llu\n",i,clo->offsets[i]);

   
 } else {
   printk(KERN_ERR "%s: file does not have an index, use sgzip to regenerate index\n",
	  cloop_name);
   error=-EBADF; goto error_release;
 };

  { /* Search for largest block rather than estimate. KK. */
   int i;
   for(i=0;i<total_offsets-1;i++)
    {
     loff_t d=(clo->offsets[i+1]) - (clo->offsets[i]);
     largest_block=MAX(largest_block,d);
    };

   printk("%s: %s: %lu blocks, %u bytes/block, largest block is %lu bytes.\n",
          cloop_name, filename, (clo->head.x.num_blocks),
          (clo->head.block_size), largest_block);
  }

/* Combo kmalloc used too large chunks (>130000). */
 clo->buffer = vmalloc((clo->head.block_size));
 if(!clo->buffer)
  {
   printk(KERN_ERR "%s: out of memory for buffer %lu\n",
          cloop_name, (unsigned long) (clo->head.block_size));
   error=-ENOMEM; goto error_release_free;
  }

 clo->compressed_buffer = vmalloc(largest_block);

 if(!clo->compressed_buffer)
  {
   printk(KERN_ERR "%s: out of memory for compressed buffer %lu\n",
          cloop_name, largest_block);
   error=-ENOMEM; goto error_release_free_buffer;
  }
 clo->zstream.workspace = vmalloc(zlib_inflate_workspacesize());
 if(!clo->zstream.workspace)
  {
   printk(KERN_ERR "%s: out of mem for zlib working area %u\n",
          cloop_name, zlib_inflate_workspacesize());
   error=-ENOMEM; goto error_release_free_all;
  }
 zlib_inflateInit(&clo->zstream);

 clo->buffered_blocknum = -1;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
 cloop_sizes[cloop_num] = (clo->head.x.num_blocks)
                      * ( (clo->head.block_size) / BLOCK_SIZE );
 /* this seems to be the maximum allowed blocksize (Kernel limit) */
 cloop_blksizes[cloop_num] = PAGE_SIZE;
#else
 set_capacity(clo->disk, (sector_t)((clo->head.num_blocks)*((clo->head.block_size)>>9)));
#endif
 return error;

error_release_free_all:
 vfree(clo->compressed_buffer);
 clo->compressed_buffer=NULL;
error_release_free_buffer:
 vfree(clo->buffer);
 clo->buffer=NULL;
error_release_free:
 vfree(clo->offsets);
 clo->offsets=NULL;
error_release:
 if(bbuf) vfree(bbuf);
 clo->backing_file=NULL;
 return error;
}

/* Code adapted from Theodore Ts'o's linux/drivers/block/loop.c */ 
/* Get file from ioctl arg (losetup) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
static int clo_set_fd(int cloop_num, struct file *clo_file, kdev_t dev,
		       unsigned int arg)
#else
static int clo_set_fd(int cloop_num, struct file *clo_file, struct block_device *bdev,
		       unsigned int arg)
#endif
{
 struct cloop_device *clo=&cloop_dev[cloop_num];
 struct file *file=NULL;
 int error = 0;

 /* Already an allocated file present */
 if(clo->backing_file) return -EBUSY;
 file = fget(arg); /* get filp struct from ioctl arg fd */
 if(!file) return -EBADF;
 error=clo_set_file(cloop_num,file,"losetup_file");
 if(error) fput(file);
 return error;
}

static int clo_clr_fd(int cloop_num, struct block_device *bdev)
{
 struct cloop_device *clo = &cloop_dev[cloop_num];
 struct file *filp = clo->backing_file;

 if(clo->refcnt > 1)	/* we needed one fd for the ioctl */
   return -EBUSY;
 if(filp==NULL) return -EINVAL;
 if(filp!=initial_file) fput(filp);
 else { filp_close(initial_file,0); initial_file=NULL; }
 clo->backing_file  = NULL;
 clo->backing_inode = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
 cloop_sizes[cloop_num] = 0;
 cloop_blksizes[cloop_num] = 0;
#else
 invalidate_bdev(bdev, 0);
 set_capacity(clo->disk, 0);
#endif
 return 0;
}

static int clo_ioctl(struct inode *inode, struct file *file,
	unsigned int cmd, unsigned long arg)
{
	struct cloop_device *clo;
	int cloop_num, err=0;

	if (!inode) return -EINVAL;
	if (MAJOR(inode->i_rdev) != MAJOR_NR) {
		printk(KERN_WARNING "cloop_ioctl: pseudo-major != %d\n",
		       MAJOR_NR);
		return -ENODEV;
	}
	cloop_num = MINOR(inode->i_rdev);
	if (cloop_num >= max_cloop) return -ENODEV;
	clo = &cloop_dev[cloop_num];
	switch (cmd) { /* We use the same ioctls that loop does */
	case LOOP_SET_FD:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
	 err = clo_set_fd(cloop_num, file, inode->i_rdev, arg);
#else
	 err = clo_set_fd(cloop_num, file, inode->i_bdev, arg);
#endif
	 break;
	case LOOP_CLR_FD:
	 err = clo_clr_fd(cloop_num, inode->i_bdev);
	 break;
        case LOOP_SET_STATUS:
        case LOOP_GET_STATUS:
	 err=0; break;
	default:
	 err = -EINVAL;
	}
	return err;
}


static int clo_open(struct inode *inode, struct file *file)
{
 int cloop_num;
 if(!inode) return -EINVAL;

 if(MAJOR(inode->i_rdev) != MAJOR_NR)
  {
   printk(KERN_WARNING "%s: pseudo-major != %d\n", cloop_name, MAJOR_NR);
   return -ENODEV;
  }

 cloop_num=MINOR(inode->i_rdev);
 if(cloop_num >= max_cloop) return -ENODEV;

 /* Allow write open for ioctl, but not for mount. */
 /* losetup uses write-open and flags=0x8002 to set a new file */
 if((file->f_mode & FMODE_WRITE) && !(file->f_flags & 0x2))
  {
   printk(KERN_WARNING "%s: Can't open device read-write\n", cloop_name);
   return -EROFS;
  }

 cloop_dev[cloop_num].refcnt+=1;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
 MOD_INC_USE_COUNT;
#endif
 return 0;
}

static int clo_close(struct inode *inode, struct file *file)
{
 int cloop_num, err=0;

 if(!inode) return 0;

 if(MAJOR(inode->i_rdev) != MAJOR_NR)
  {
   printk(KERN_WARNING "%s: pseudo-major != %d\n", cloop_name, MAJOR_NR);
   return 0;
  }

 cloop_num=MINOR(inode->i_rdev);
 if(cloop_num >= max_cloop) return 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
 err = fsync_dev(inode->i_rdev);
#endif
 cloop_dev[cloop_num].refcnt-=1;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
 MOD_DEC_USE_COUNT;
#endif
 return err;
}

static struct block_device_operations clo_fops =
{
        owner:		THIS_MODULE,
        open:           clo_open,
        release:        clo_close,
        ioctl:          clo_ioctl
};

static int cloop_init(void)
{
 int i, error=0;
 printk("%s: Initializing %s v"CLOOP_VERSION"\n", cloop_name, cloop_name);

 for(i=0;i<max_cloop;i++)
  {
   memset(&cloop_dev[i],0,sizeof(struct cloop_device));
   init_MUTEX(&cloop_dev[i].clo_lock);
  }

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
 if(devfs_register_blkdev(MAJOR_NR, cloop_name, &clo_fops))
#else
 if(register_blkdev(MAJOR_NR, cloop_name))
#endif
  {
   printk(KERN_WARNING "%s: Unable to get major %d for cloop\n",
          cloop_name, MAJOR_NR);
   return -EINVAL;
  }

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
 blk_size[MAJOR_NR] = cloop_sizes;
 blksize_size[MAJOR_NR] = cloop_blksizes;
 blk_queue_make_request(BLK_DEFAULT_QUEUE(MAJOR_NR), make_clo_request);

 for (i=0;i<max_cloop;i++) register_disk(NULL,MKDEV(MAJOR_NR,i),1,&clo_fops,0);

 devfs_handle = devfs_mk_dir(NULL, "cloop", NULL);
 devfs_register_series(devfs_handle, "%u", max_cloop, DEVFS_FL_DEFAULT,
		 MAJOR_NR, 0,
		 S_IFBLK | S_IRUSR | S_IWUSR | S_IRGRP,
		 &clo_fops, NULL);
#else
 devfs_mk_dir("cloop");
 for(i=0; i<max_cloop; i++) 
   if(!(cloop_dev[i].disk = alloc_disk(1))) goto out_disks;
 for(i=0; i<max_cloop; i++)
  {
   struct cloop_device *clo = &cloop_dev[i];
   clo->clo_queue = blk_alloc_queue(GFP_KERNEL);
   if(!clo->clo_queue) goto out_mem;
   blk_queue_make_request(clo->clo_queue, make_clo_request);
   clo->disk->queue = clo->clo_queue;
   clo->clo_queue->queuedata = clo;
   clo->disk->queue = clo->clo_queue;
   clo->disk->major = MAJOR_NR;
   clo->disk->first_minor = i;
   clo->disk->fops = &clo_fops;
   sprintf(clo->disk->disk_name, "%s%d", cloop_name, i);
   sprintf(clo->disk->devfs_name, "%s/%d", cloop_name, i);
   clo->disk->private_data = clo;
   add_disk(clo->disk);
  }
#endif

 printk(KERN_INFO "cloop: loaded (max %d devices)\n", max_cloop);

 if(file) /* global file name for first cloop-Device is a module option string. */
  {
   initial_file=filp_open(file,0x00,0x00);
   if(initial_file==NULL||IS_ERR(initial_file))
    {
     printk(KERN_ERR
            "%s: Unable to get file %s for cloop device\n",
            cloop_name, file);
     return -EINVAL;
    }
   error=clo_set_file(0,initial_file,file);
   if(error) { i=max_cloop; goto out_mem; }
  }

 return 0;

out_mem:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
 while (i--) blk_put_queue(cloop_dev[i].clo_queue);
 i = max_cloop;
out_disks:
 while (i--) { put_disk(cloop_dev[i].disk); cloop_dev[i].disk=NULL; }
#endif
 unregister_blkdev(MAJOR_NR,cloop_name);
/* error_filp_close: */
 if(initial_file) filp_close(initial_file,0); initial_file=NULL;
 cloop_dev[0].backing_file=NULL;
 return error;
}

static void cloop_exit(void) 
{
 int i;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
 if(devfs_unregister_blkdev(MAJOR_NR, cloop_name) != 0)
#else
 devfs_remove(cloop_name);
 if(unregister_blkdev(MAJOR_NR, cloop_name) != 0)
#endif
   printk(KERN_WARNING "%s: cannot unregister block device\n", cloop_name);
 for(i=0;i<max_cloop;i++)
  {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
   del_gendisk(cloop_dev[i].disk);
   blk_put_queue(cloop_dev[i].clo_queue);
   put_disk(cloop_dev[i].disk);
#endif
   if(cloop_dev[i].offsets) vfree(cloop_dev[i].offsets);
   if(cloop_dev[i].buffer)  vfree(cloop_dev[i].buffer);
   if(cloop_dev[i].compressed_buffer) vfree(cloop_dev[i].compressed_buffer);
   zlib_inflateEnd(&cloop_dev[i].zstream);
   if(cloop_dev[i].zstream.workspace) vfree(cloop_dev[i].zstream.workspace);
   if(cloop_dev[i].backing_file && cloop_dev[i].backing_file!=initial_file)
    {
     fput(cloop_dev[i].backing_file);
    }
  }
 if(initial_file) filp_close(initial_file,0);
 printk("%s: unloaded.\n", cloop_name);
}

/* The cloop init and exit function registration (especially needed for Kernel 2.6) */
module_init(cloop_init);
module_exit(cloop_exit);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=";
#endif
