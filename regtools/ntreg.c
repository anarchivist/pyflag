/*
 * ntreg.c - NT Registry Hive access library
 *
 * 2003-jan: Allocation of new data, supports adding/deleting keys & stuff.
 *           Missing is expanding the file.
 * 2003-jan: Seems there may be garbage pages at end of file, not zero pages
 *           now stops enumerating at first non 'hbin' page.
 * 
 * NOTE: The API is not frozen. It can and will change every release.
 *
 * Copyright (c) 1997-2003 Petter Nordahl-Hagen.
 * Freely distributable in source or binary for noncommercial purposes,
 * but I allow some exceptions to this.
 * Please see the COPYING file for more details on
 * copyrights & credits.
 *  
 * THIS SOFTWARE IS PROVIDED BY PETTER NORDAHL-HAGEN `AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */ 

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "ntreg.h"

const char ntreg_version[] = "ntreg lib routines, v0.90 030126 , (c) Petter N Hagen";

char *val_types[REG_MAX+1] = {
  "REG_NONE", "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_DWORD",       /* 0 - 4 */
  "REG_DWORD_BIG_ENDIAN", "REG_LINK",                                     /* 5 - 6 */
  "REG_MULTI_SZ", "REG_RESOUCE_LIST", "REG_FULL_RES_DESC", "REG_RES_REQ", /* 7 - 10 */
};

/* Utility routines */
char *str_dup( const char *str )
{
    char *str_new;

    if (!str)
        return 0 ;

    CREATE( str_new, char, strlen(str) + 1 );
    strcpy( str_new, str );
    return str_new;
}

int fmyinput(char *prmpt, char *ibuf, int maxlen)
{
   
   printf("%s",prmpt);
   
   fgets(ibuf,maxlen+1,stdin);
   
   ibuf[strlen(ibuf)-1] = 0;
   
   return(strlen(ibuf));
}

/* Print len number of hexbytes */

void hexprnt(char *s, unsigned char *bytes, int len)
{
int i;

   printf("%s",s);
   for (i = 0; i < len; i++) {
      printf("%02x ",bytes[i]);
   }
   printf("\n");
}

/* HexDump all or a part of some buffer */

void hexdump(char *hbuf, int start, int stop, int ascii)
{
   char c;
   int diff,i;
   
   while (start < stop ) {
      
      diff = stop - start;
      if (diff > 16) diff = 16;
      
      printf(":%05X  ",start);

      for (i = 0; i < diff; i++) {
	 printf("%02X ",(unsigned char)*(hbuf+start+i));
      }
      if (ascii) {
	for (i = diff; i < 16; i++) printf("   ");
	for (i = 0; i < diff; i++) {
	  c = *(hbuf+start+i);
	  printf("%c", isprint(c) ? c : '.');
	}
      }
      printf("\n");
      start += 16;
   }
}

/* General search routine, find something in something else */
int find_in_buf(char *buf, char *what, int sz, int len, int start)
{
   int i;
   
   for (; start < sz; start++) {
      for (i = 0; i < len; i++) {
	if (*(buf+start+i) != *(what+i)) break;
      }
      if (i == len) return(start);
   }
   return(0);
}

/* Get INTEGER from memory. This is probably low-endian specific? */
int get_int( char *array )
{
	return ((array[0]&0xff) + ((array[1]<<8)&0xff00) +
		   ((array[2]<<16)&0xff0000) +
		   ((array[3]<<24)&0xff000000));
}


/* Quick and dirty UNICODE to std. ascii */

void cheap_uni2ascii(char *src, char *dest, int l)
{
   
   for (; l > 0; l -=2) {
      *dest = *src;
      dest++; src +=2;
   }
   *dest = 0;
}


/* Quick and dirty ascii to unicode */

void cheap_ascii2uni(char *src, char *dest, int l)
{
   for (; l > 0; l--) {
      *dest++ = *src++;
      *dest++ = 0;

   }
}

void skipspace(char **c)
{
   while( **c == ' ' ) (*c)++;
}

int gethex(char **c)
{
   int value;
   
   skipspace(c);
   
   if (!(**c)) return(0);

   sscanf(*c,"%x",&value);

   while( **c != ' ' && (**c)) (*c)++;

   return(value);
}
   
/* Get a string of HEX bytes (space separated),
 * or if first char is ' get an ASCII string instead.
 */

int gethexorstr(char **c, char *wb)
{
   int l = 0;
   
   skipspace(c);
   
   if ( **c == '\'') {
      (*c)++;
      while ( **c ) {
	 *(wb++) = *((*c)++);
	 l++;
      }
   } else {
      do {
	 *(wb++) = gethex(c);
	 l++;
	 skipspace(c);
      } while ( **c );
   }
   return(l);
}

/* Simple buffer debugger, returns 1 if buffer dirty/edited */

int debugit(char *buf, int sz)
{


   char inbuf[100],whatbuf[100],*bp;

   int dirty=0,to,from,l,i,j,wlen,cofs = 0;
   
   printf("Buffer debugger. '?' for help.\n");
   
   while (1) {
      l = fmyinput(".",inbuf,90);
      bp = inbuf;

      skipspace(&bp);

      if (l > 0 && *bp) {
	 switch(*bp) {
	  case 'd' :
	    bp++;
	    if (*bp) {
	       from = gethex(&bp);
	       to   = gethex(&bp);
	    } else {
	       from = cofs; to = 0;
	    }
	    if (to == 0) to = from + 0x100;
	    if (to > sz) to = sz;
	    hexdump(buf,from,to,1);
	    cofs = to;
	    break;
	  case 'a' :
	    bp++;
	    if (*bp) {
	       from = gethex(&bp);
	       to   = gethex(&bp);
	    } else {
	       from = cofs; to = 0;
	    }
	    if (to == 0) to = from + 0x100;
	    if (to > sz) to = sz;
	    hexdump(buf,from,to,0);
	    cofs = to;
	    break;
#if 0
	  case 'k' :
	    bp++;
	    if (*bp) {
	       from = gethex(&bp);
	    } else {
	       from = cofs;
	    }
	    if (to > sz) to = sz;
	    parse_block(from,1);
	    cofs = to;
	    break;
#endif
#if 0
	  case 'l' :
	    bp++;
	    if (*bp) {
	       from = gethex(&bp);
	    } else {
	       from = cofs;
	    }
	    if (to > sz) to = sz;
	    nk_ls(from+4,0);
	    cofs = to;
	    break;
#endif
	  case 'q':
	    return(0);
	    break;
	  case 's':
	    if (!dirty) printf("Buffer has not changed, no need to write..\n");
	    return(dirty);
	    break;
	  case 'h':
	    bp++;
	    if (*bp == 'a') {
	       from = 0;
	       to = sz;
	       bp++;
	    } else {
	       from = gethex(&bp);
	       to   = gethex(&bp);
	    }
	    wlen = gethexorstr(&bp,whatbuf);
	    if (to > sz) to = sz;
	    printf("from: %x, to: %x, wlen: %d\n",from,to,wlen);
	    for (i = from; i < to; i++) {
	       for (j = 0; j < wlen; j++) {
		  if ( *(buf+i+j) != *(whatbuf+j)) break;
	       }
	       if (j == wlen) printf("%06x ",i);
	    }
	    printf("\n");
	    break;
	  case ':':
	    bp++;
	    if (!*bp) break;
	    from = gethex(&bp);
	    wlen = gethexorstr(&bp,whatbuf);
	    
	    printf("from: %x, wlen: %d\n",from,wlen);

	    memcpy(buf+from,whatbuf,wlen);
	    dirty = 1;
	    break;
#if 0
	  case 'p':
	    j = 0;
	    if (*(++bp) != 0) {
	       from = gethex(&bp);
	    }
	    if (*(++bp) != 0) {
	       j = gethex(&bp);
	    }
	    printf("from: %x, rid: %x\n",from,j);
	    seek_n_destroy(from,j,500,0);
	    break;
#endif
	  case '?':
	    printf("d [<from>] [<to>] - dump buffer within range\n");
	    printf("a [<from>] [<to>] - same as d, but without ascii-part (for cut'n'paste)\n");
	    printf(": <offset> <hexbyte> [<hexbyte> ...] - change bytes\n");
	    printf("h <from> <to> <hexbyte> [<hexbyte> ...] - hunt (search) for bytes\n");
	    printf("ha <hexbyte> [<hexbyte] - Hunt all (whole buffer)\n");
	    printf("s - save & quit\n");
	    printf("q - quit (no save)\n");
	    printf("  instead of <hexbyte> etc. you may give 'string to enter/search a string\n");
	    break;
	  default:
	    printf("?\n");
	    break;
	 }
      }
   }
}


/* ========================================================================= */

/* The following routines are mostly for debugging, I used it
 * much during discovery. the -t command line option uses it,
 * also the 'st' and 's' from the editor & hexdebugger.
 * All offsets shown in these are unadjusted (ie you must add
 * headerpage (most often 0x1000) to get file offset)
 */

/* Parse the nk datablock
 * vofs = offset into struct (after size linkage)
 */
void parse_nk(struct hive *hdesc, int vofs, int blen)
{

  struct nk_key *key;
  int i;

  printf("== nk at offset %0x\n",vofs);

#define D_OFFS(o) ( (void *)&(key->o)-(void *)hdesc->buffer-vofs )

  key = (struct nk_key *)(hdesc->buffer + vofs);
  printf("%04x   type              = 0x%02x %s\n", D_OFFS(type)  , key->type,
	                           (key->type == KEY_ROOT ? "ROOT_KEY" : "") );
  printf("%04x   timestamp skipped\n", D_OFFS(timestamp) );
  printf("%04x   parent key offset = 0x%0lx\n", D_OFFS(ofs_parent) ,key->ofs_parent);
  printf("%04x   number of subkeys = %ld\n", D_OFFS(no_subkeys),key->no_subkeys);
  printf("%04x   lf-record offset  = 0x%0lx\n",D_OFFS(ofs_lf),key->ofs_lf);
  printf("%04x   number of values  = %ld\n", D_OFFS(no_values),key->no_values);
  printf("%04x   val-list offset   = 0x%0lx\n",D_OFFS(ofs_vallist),key->ofs_vallist);
  printf("%04x   sk-record offset  = 0x%0lx\n",D_OFFS(ofs_sk),key->ofs_sk);
  printf("%04x   classname offset  = 0x%0lx\n",D_OFFS(ofs_classnam),key->ofs_classnam);
  printf("%04x   *unused?*         = 0x%0lx\n",D_OFFS(dummy4),key->dummy4);
  printf("%04x   name length       = %d\n", D_OFFS(len_name),key->len_name);
  printf("%04x   classname length  = %d\n", D_OFFS(len_classnam),key->len_classnam);

  printf("%04x   Key name: <",D_OFFS(keyname) );
  for(i = 0; i < key->len_name; i++) putchar(key->keyname[i]);
  printf(">\n== End of key info.\n");

}

/* Parse the vk datablock
 * vofs = offset into struct (after size linkage)
 */
void parse_vk(struct hive *hdesc, int vofs, int blen)
{
  struct vk_key *key;
  int i;

  printf("== vk at offset %0x\n",vofs);


  key = (struct vk_key *)(hdesc->buffer + vofs);
  printf("%04x   name length       = %d (0x%0x)\n", D_OFFS(len_name),
	                             key->len_name, key->len_name  );
  printf("%04x   length of data    = %ld (0x%0lx)\n", D_OFFS(len_data),
	                             key->len_data, key->len_data  );
  printf("%04x   data offset       = 0x%0lx\n",D_OFFS(ofs_data),key->ofs_data);
  printf("%04x   value type        = 0x%0lx  %s\n", D_OFFS(val_type), key->val_type,
                 (key->val_type <= REG_MAX ? val_types[key->val_type] : "(unknown)") ) ;

  printf("%04x   flag              = 0x%0x\n",D_OFFS(flag),key->flag);
  printf("%04x   *unused?*         = 0x%0x\n",D_OFFS(dummy1),key->dummy1);

  printf("%04x   Key name: <",D_OFFS(keyname) );
  for(i = 0; i < key->len_name; i++) putchar(key->keyname[i]);
  printf(">\n== End of key info.\n");

}

/* Parse the sk datablock
 * Gee, this is the security info. Who cares? *evil grin*
 * vofs = offset into struct (after size linkage)
 */
void parse_sk(struct hive *hdesc, int vofs, int blen)
{
  struct sk_key *key;
  /* int i; */

  printf("== sk at offset %0x\n",vofs);

  key = (struct sk_key *)(hdesc->buffer + vofs);
  printf("%04x   *unused?*         = %d\n"   , D_OFFS(dummy1),     key->dummy1    );
  printf("%04x   Offset to prev sk = 0x%0lx\n", D_OFFS(ofs_prevsk), key->ofs_prevsk);
  printf("%04x   Offset to next sk = 0x%0lx\n", D_OFFS(ofs_nextsk), key->ofs_nextsk);
  printf("%04x   Usage counter     = %ld (0x%0lx)\n", D_OFFS(no_usage),
	                                            key->no_usage,key->no_usage);
  printf("%04x   Security data len = %ld (0x%0lx)\n", D_OFFS(len_sk),
	                                            key->len_sk,key->len_sk);

  printf("== End of key info.\n");

}


/* Parse the lf datablock (>4.0 'nk' offsets lookuptable)
 * vofs = offset into struct (after size linkage)
 */
void parse_lf(struct hive *hdesc, int vofs, int blen)
{
  struct lf_key *key;
  int i;

  printf("== lf at offset %0x\n",vofs);

  key = (struct lf_key *)(hdesc->buffer + vofs);
  printf("%04x   number of keys    = %d\n", D_OFFS(no_keys), key->no_keys  );

  for(i = 0; i < key->no_keys; i++) {
    printf("%04x      %3d   Offset: 0x%0lx  - <%c%c%c%c>\n", 
	   D_OFFS(hash[i].ofs_nk), i,
	   key->hash[i].ofs_nk,
           key->hash[i].name[0],
           key->hash[i].name[1],
           key->hash[i].name[2],
           key->hash[i].name[3] );
  }

  printf("== End of key info.\n");

}

/* Parse the lh datablock (WinXP offsets lookuptable)
 * vofs = offset into struct (after size linkage)
 * The hash is most likely a base 37 conversion of the name string
 */
void parse_lh(struct hive *hdesc, int vofs, int blen)
{
  struct lf_key *key;
  int i;

  printf("== lh at offset %0x\n",vofs);

  key = (struct lf_key *)(hdesc->buffer + vofs);
  printf("%04x   number of keys    = %d\n", D_OFFS(no_keys), key->no_keys  );

  for(i = 0; i < key->no_keys; i++) {
    printf("%04x      %3d   Offset: 0x%0lx  - <hash: %08lx>\n", 
	   D_OFFS(lh_hash[i].ofs_nk), i,
	   key->lh_hash[i].ofs_nk,
           key->lh_hash[i].hash );
  }

  printf("== End of key info.\n");

}


/* Parse the li datablock (3.x 'nk' offsets list)
 * vofs = offset into struct (after size linkage)
 */
void parse_li(struct hive *hdesc, int vofs, int blen)
{
  struct li_key *key;
  int i;

  printf("== li at offset %0x\n",vofs);

#define D_OFFS(o) ( (void *)&(key->o)-(void *)hdesc->buffer-vofs )

  key = (struct li_key *)(hdesc->buffer + vofs);
  printf("%04x   number of keys    = %d\n", D_OFFS(no_keys), key->no_keys  );

  for(i = 0; i < key->no_keys; i++) {
    printf("%04x      %3d   Offset: 0x%0lx\n", 
	   D_OFFS(hash[i].ofs_nk), i,
	   key->hash[i].ofs_nk);
  }
  printf("== End of key info.\n");

}


/* Parse the datablock
 * vofs = offset into struct (after size linkage)
 */

int parse_block(struct hive *hdesc, int vofs,int verbose)
{
  unsigned short id;
  int seglen;

  seglen = get_int(hdesc->buffer+vofs);  

  if (verbose || seglen == 0) {
    printf("** Block at offset %0x\n",vofs);
    printf("seglen: %d, %u, 0x%0x\n",seglen,seglen,seglen);
  }
  if (seglen == 0) {
    printf("Whoops! FATAL! Zero data block size! (not registry or corrupt file?)\n");
    debugit(hdesc->buffer,hdesc->size);
    return(0);
  }
  
  if (seglen < 0) {
    seglen = -seglen;
    hdesc->usetot += seglen;
    hdesc->useblk++;
    if (verbose) {
      printf("USED BLOCK: %d, 0x%0x\n",seglen,seglen);
      /*      hexdump(hdesc->buffer,vofs,vofs+seglen+4,1); */
    }
  } else {
    hdesc->unusetot += seglen;
    hdesc->unuseblk++;
    bzero(hdesc->buffer+vofs+4,seglen-4);

    if (verbose) {
      printf("FREE BLOCK!\n"); 
      /*      hexdump(hdesc->buffer,vofs,vofs+seglen+4,1); */
    }
  }


  /*  printf("Seglen: 0x%02x\n",seglen & 0xff ); */

  vofs += 4;
  id = (*(hdesc->buffer + vofs)<<8) + *(hdesc->buffer+vofs+1);

  if (verbose) {
    switch (id) {
    case 0x6e6b: /* nk */
      parse_nk(hdesc, vofs, seglen);
      break;
    case 0x766b: /* vk */
      parse_vk(hdesc, vofs, seglen);
      break;
    case 0x6c66: /* lf */
      parse_lf(hdesc, vofs, seglen);
      break;
    case 0x6c68: /* lh */
      parse_lh(hdesc, vofs, seglen);
      break;
    case 0x6c69: /* li */
      parse_li(hdesc, vofs, seglen);
      break;
    case 0x736b: /* sk */
      parse_sk(hdesc, vofs, seglen);
      break;
    default:
      printf("value data, or not handeled yet!\n");
      break;
    }
  }
  return(seglen);
}

/* ================================================================ */
/* Scan and allocation routines */

/* Find start of page given a current pointer into the buffer
 * hdesc = hive
 * vofs = offset pointer into buffer
 * returns: offset to start of page (and page header)
 */

int find_page_start(struct hive *hdesc, int vofs)
{
  int r,prev;
  struct hbin_page *h;

  /* Again, assume start at 0x1000 */

  r = 0x1000;
  while (r < hdesc->size) {
    prev = r;
    h = (struct hbin_page *)(hdesc->buffer + r);
    if (h->id != 0x6E696268) return(0);
    if (h->ofs_next == 0) {
      printf("find_page_start: zero len or ofs_next found in page at 0x%x\n",r);
      return(0);
    }
    r += h->ofs_next;
    if (r > vofs) return (prev);
  }
  return(0);
}

/* Find free space in page
 * size = requested size in bytes
 * pofs = offset to start of actual page header
 * returns: offset to free block, or 0 for error
 */

#define FB_DEBUG 0

int find_free_blk(struct hive *hdesc, int pofs, int size)
{
  int vofs = pofs + 0x20;
  int seglen;
  struct hbin_page *p;
  
  p = (struct hbin_page *)(hdesc->buffer + pofs);

  while (vofs-pofs < p->ofs_next) {

    seglen = get_int(hdesc->buffer+vofs);  

#if FB_DEBUG
    printf("** Block at offset %0x\n",vofs);
    printf("seglen: %d, %u, 0x%0x\n",seglen,seglen,seglen);
#endif

    if (seglen == 0) {
      printf("find_free_blk: FATAL! Zero data block size! (not registry or corrupt file?)\n");
      debugit(hdesc->buffer,hdesc->size);
      return(0);
    }
    
    if (seglen < 0) {
      seglen = -seglen;
#if FB_DEBUG
	printf("USED BLOCK: %d, 0x%0x\n",seglen,seglen);
#endif
	/*      hexdump(hdesc->buffer,vofs,vofs+seglen+4,1); */
    } else {
#if FB_DEBUG
	printf("FREE BLOCK!\n"); 
#endif
	/*      hexdump(hdesc->buffer,vofs,vofs+seglen+4,1); */
	if (seglen >= size) {
#if FB_DEBUG
	  printf("find_free_blk: found size %d block at 0x%x\n",seglen,vofs);
#endif
	  return(vofs);
	}
    }
    vofs += seglen;
  }
  return(0);
  
}

#undef FB_DEBUG

/* Search pages from start to find free block
 * hdesc - hive
 * size - space requested, in bytes
 * returns: offset to free block, 0 if not found or error
 */

int find_free(struct hive *hdesc, int size)
{
  int r,blk;
  struct hbin_page *h;

  /* Align to 8 byte boundary */
  if (size & 7) size += (8 - (size & 7));

  /* Again, assume start at 0x1000 */

  r = 0x1000;
  while (r < hdesc->size) {
    h = (struct hbin_page *)(hdesc->buffer + r);
    if (h->id != 0x6E696268) return(0);
    if (h->ofs_next == 0) {
      printf("find_free: zero len or ofs_next found in page at 0x%x\n",r);
      return(0);
    }
    blk = find_free_blk(hdesc,r,size);
    if (blk) return (blk);
    r += h->ofs_next;
  }
  return(0);
}

/* Allocate a block of requested size if possible
 * hdesc - hive
 * pofs - If >0 will try this page first (ptr may be inside page)
 * size - number of bytes to allocate
 * returns: 0 - failed, else pointer to allocated block.
 * This function WILL CHANGE THE HIVE (change block linkage) if it
 * succeeds.
 */

int alloc_block(struct hive *hdesc, int ofs, int size)
{
  int pofs = 0;
  int blk = 0;
  int trail, trailsize, oldsz;

  if (hdesc->state & HMODE_NOALLOC) {
    printf("alloc_block: ERROR: Hive %s is in no allocation safe mode,"
	   "new space not allocated. Operation will fail!\n", hdesc->filename);
    return(0);
  }

  size += 4;  /* Add linkage */
  if (size & 7) size += (8 - (size & 7));

  /* Check current page first */
  if (ofs) {
    pofs = find_page_start(hdesc,ofs);
    blk = find_free_blk(hdesc,pofs,size);
  }

  /* Then check whole hive */
  if (!blk) {
    blk = find_free(hdesc,size);
  }

  if (blk) {  /* Got the space */
    oldsz = get_int(hdesc->buffer+blk);
#if 0
    printf("Block at         : %x\n",blk);
    printf("Old block size is: %x\n",oldsz);
    printf("New block size is: %x\n",size);
#endif
    trailsize = oldsz - size;

    if (trailsize == 4) {
      trailsize = 0;
      size += 4;
    }

 #if 1
    if (trailsize & 7) { /* Trail must be 8 aligned */
      trailsize -= (8 - (trailsize & 7));
      size += (8 - (trailsize & 7));
    }
    if (trailsize == 4) {
      trailsize = 0;
      size += 4;
    }
#endif

#if 0
    printf("trail after comp: %x\n",trailsize);
    printf("size  after comp: %x\n",size);
#endif

    /* Now change pointers on this to reflect new size */
    *(int *)((hdesc->buffer)+blk) = -(size);
    /* If the fit was exact (unused block was same size as wee need)
     * there is no need for more, else make free block after end
     * of newly allocated one */

    hdesc->useblk++;
    hdesc->unuseblk--;
    hdesc->usetot += size;
    hdesc->unusetot -= size;

    if (trailsize) {
      trail = blk + size;

      *(int *)((hdesc->buffer)+trail) = (int)trailsize;

      hdesc->useblk++;    /* This will keep blockcount */
      hdesc->unuseblk--;
      hdesc->usetot += 4; /* But account for more linkage bytes */
      hdesc->unusetot -= 4;

    }  
    /* Clear the block data, makes it easier to debug */
    bzero( (void *)(hdesc->buffer+blk+4), size-4);

    hdesc->state |= HMODE_DIRTY;
    
    return(blk);
  } else {
    printf("alloc_block: failed to alloc %d bytes, and hive expansion not implemented yet!\n",size);
  }
  return(0);
}

/* Free a block in registry
 * hdesc - hive
 * blk   - offset of block, MUST POINT TO THE LINKAGE!
 * returns bytes freed (incl linkage bytes) or 0 if fail
 * Will CHANGE HIVE IF SUCCESSFUL (changes linkage)
 */

#define FB_DEBUG 1

int free_block(struct hive *hdesc, int blk)
{
  int pofs,vofs,seglen,prev,next,nextsz,prevsz,size;
  struct hbin_page *p;

  if (hdesc->state & HMODE_NOALLOC) {
    printf("free_block: ERROR: Hive %s is in no allocation safe mode,"
	   "space not freed. Operation will fail!\n", hdesc->filename);
    return(0);
  }

  size = get_int(hdesc->buffer+blk);
  if (size >= 0) {
    printf("free_block: trying to free already free block!\n");
    return(0);
  }
  size = -size;

  /* So, we must find start of the block BEFORE us */
  pofs = find_page_start(hdesc,blk);
  if (!pofs) return(0);

  p = (struct hbin_page *)(hdesc->buffer + pofs);
  vofs = pofs + 0x20;

  while (vofs-pofs < p->ofs_next) {

    seglen = get_int(hdesc->buffer+vofs);  

    if (seglen == 0) {
      printf("free_block: EEEK! Zero data block size! (not registry or corrupt file?)\n");
      debugit(hdesc->buffer,hdesc->size);
      return(0);
    }
    
    if (seglen < 0) {
      seglen = -seglen;
	/*      hexdump(hdesc->buffer,vofs,vofs+seglen+4,1); */
    } 
    prev = vofs;
    vofs += seglen;
    if (vofs == blk) break;
  }

  if (vofs != blk) {
    printf("free_block: ran off end of page!?!? Error in chains?\n");
    return(0);
  }

  /* We also need details on next block (unless at end of page) */
  next = blk + size;

  prevsz = get_int(hdesc->buffer+prev);
  if (next >= p->ofs_next) nextsz = get_int(hdesc->buffer+next);

#if 0
  printf("offset prev : %x , blk: %x , next: %x\n",prev,blk,next);
  printf("size   prev : %x , blk: %x , next: %x\n",prevsz,size,nextsz);
#endif

  /* Now check if next block is free, if so merge it with the one to be freed */
  if ( (next >= p->ofs_next) && nextsz > 0) {
    size += nextsz;   /* Swallow it in current block */
    hdesc->useblk--;
    hdesc->usetot -= 4;
    hdesc->unusetot -= 4;
  }

  /* Now free the block (possibly with ajusted size as above) */
  /*  bzero( (void *)(hdesc->buffer+blk), size); */
  *(int *)((hdesc->buffer)+blk) = (int)size;
  hdesc->usetot -= size;
  hdesc->unusetot -= size;
  hdesc->unuseblk--;

  hdesc->state |= HMODE_DIRTY;
 
  /* Check if previous block is also free, if so, merge.. */
  if (prevsz > 0) {
    hdesc->usetot -= prevsz;
    hdesc->unusetot += prevsz;
    prevsz += size;
    /* And swallow current.. */
    /*   bzero( (void *)(hdesc->buffer+prev), prevsz); */
    *(int *)((hdesc->buffer)+prev) = (int)prevsz;
    hdesc->useblk--;
    return(prevsz);
  }
  return(size);
}



/* ================================================================ */

/* ** Registry manipulation routines ** */



/* "directory scan", return next name/pointer of a subkey on each call
 * nkofs = offset to directory to scan
 * lfofs = pointer to int to hold the current scan position,
 *         set position to 0 to start.
 * sptr  = pointer to struct to hold a single result
 * returns: -1 = error. 0 = end of key. 1 = more subkeys to scan
 * NOTE: caller must free the name-buffer (struct ex_data *name)
 */
int ex_next_n(struct hive *hdesc, int nkofs, int *count, int *countri, struct ex_data *sptr)
{
  struct nk_key *key, *newnkkey;
  int newnkofs;
  struct lf_key *lfkey;
  struct li_key *likey;
  struct ri_key *rikey;


  if (!nkofs) return(-1);
  key = (struct nk_key *)(hdesc->buffer + nkofs);
  if (key->id != 0x6b6e) {
    printf("ex_next error: Not a 'nk' node at 0x%0x\n",nkofs);
    return(-1);
  }

#undef EXNDEBUG

  lfkey = (struct lf_key *)(hdesc->buffer + key->ofs_lf + 0x1004);
  rikey = (struct ri_key *)(hdesc->buffer + key->ofs_lf + 0x1004);

  if (rikey->id == 0x6972) {   /* Is it extended 'ri'-block? */
#if EXNDEBUG
    printf("%d , %d\n",*countri,*count);
#endif
    if (*countri < 0 || *countri >= rikey->no_lis) { /* End of ri's? */
      return(0);
    }
    /* Get the li-struct that's current based on countri */
    likey = (struct li_key *)( hdesc->buffer + rikey->hash[*countri].ofs_li + 0x1004 ) ;
    newnkofs = likey->hash[*count].ofs_nk + 0x1000;
    /* Check if current li is exhausted */
#if EXNDEBUG
    printf("likey->no_keys = %d\n",likey->no_keys);
#endif
    if (*count >= likey->no_keys-1) { /* Last legal entry in li list? */
      (*countri)++;  /* Bump up ri count so we take next ri entry next time */
      (*count) = -1;  /* Reset li traverse counter for next round, not used later here */
    }
  } else { /* Plain handler */
    if (key->no_subkeys <= 0 || *count >= key->no_subkeys) {
      return(0);
    }
    if (lfkey->id == 0x696c) {   /* Is it 3.x 'li' instead? */
      likey = (struct li_key *)(hdesc->buffer + key->ofs_lf + 0x1004);
      newnkofs = likey->hash[*count].ofs_nk + 0x1000;
    } else {
      newnkofs = lfkey->hash[*count].ofs_nk + 0x1000;
    }
  }

  sptr->nkoffs = newnkofs;
  newnkkey = (struct nk_key *)(hdesc->buffer + newnkofs + 4);
  sptr->nk = newnkkey;

  if (newnkkey->id != 0x6b6e) {
    printf("ex_next: ERROR: not 'nk' node at 0x%0x\n",newnkofs);

    return(-1);
  } else {
    if (newnkkey->len_name <= 0) {
      printf("ex_next: nk at 0x%0x has no name!\n",newnkofs);
    } else {
      sptr->name = (char *)malloc(newnkkey->len_name+1);
      if (!sptr->name) {
	printf("FATAL! ex_next: malloc() failed! Out of memory?\n");
	abort();
      }
      strncpy(sptr->name,newnkkey->keyname,newnkkey->len_name);
      sptr->name[newnkkey->len_name] = 0;
    }
  } /* if */
  (*count)++;
  return(1);
  /*  return( *count <= key->no_subkeys); */
}

/* "directory scan" for VALUES, return next name/pointer of a value on each call
 * nkofs = offset to directory to scan
 * lfofs = pointer to int to hold the current scan position,
 *         set position to 0 to start.
 * sptr  = pointer to struct to hold a single result
 * returns: -1 = error. 0 = end of key. 1 = more values to scan
 * NOTE: caller must free the name-buffer (struct vex_data *name)
 */
int ex_next_v(struct hive *hdesc, int nkofs, int *count, struct vex_data *sptr)
{
  struct nk_key *key /* , *newnkkey */ ;
  int vkofs,vlistofs;
  int *vlistkey;
  struct vk_key *vkkey;


  if (!nkofs) return(-1);
  key = (struct nk_key *)(hdesc->buffer + nkofs);
  if (key->id != 0x6b6e) {
    printf("ex_next_v error: Not a 'nk' node at 0x%0x\n",nkofs);
    return(-1);
  }

  if (key->no_values <= 0 || *count >= key->no_values) {
    return(0);
  }

  vlistofs = key->ofs_vallist + 0x1004;
  vlistkey = (int *)(hdesc->buffer + vlistofs);

  vkofs = vlistkey[*count] + 0x1004;
  vkkey = (struct vk_key *)(hdesc->buffer + vkofs);
  if (vkkey->id != 0x6b76) {
    printf("ex_next_v: hit non valuekey (vk) node during scan at offs 0x%0x\n",vkofs);
    return(-1);
  }

  /*  parse_vk(hdesc, vkofs, 4); */

  sptr->vk = vkkey;
  sptr->vkoffs = vkofs;
  sptr->name = 0;
  sptr->size = (vkkey->len_data & 0x7fffffff);

  if (vkkey->len_name >0) {
    CREATE(sptr->name,char,vkkey->len_name+1);
    memcpy(sptr->name,vkkey->keyname,vkkey->len_name);
    sptr->name[vkkey->len_name] = 0;
  } else {
    sptr->name = str_dup("@");
  }

  sptr->type = vkkey->val_type;
  if (sptr->size) {
    if (vkkey->val_type == REG_DWORD) {
      if (vkkey->len_data & 0x80000000) {
	sptr->val = (int)(vkkey->ofs_data);
      }
    }
  } else if (vkkey->len_data == 0x80000000) { 
    /* Data SIZE is 0, high bit set: special inline case, data is DWORD and in TYPE field!! */
    /* Used a lot in SAM, and maybe in SECURITY I think */
    sptr->val = (int)(vkkey->val_type);
    sptr->size = 4;
    sptr->type = REG_DWORD;
  } else {
    sptr->val = 0;
    sptr->size = 0;
  }

  (*count)++;
  return( *count <= key->no_values );
}

/* traceback - trace nk's back to root,
 * building path string as we go.
 * nkofs  = offset to nk-node
 * path   = pointer to pathstring-buffer
 * maxlen = max length of path-buffer
 * return: length of path string
 */

int get_abs_path(struct hive *hdesc, int nkofs, char *path, int maxlen)
{
  /* int newnkofs; */
  struct nk_key *key;
  char tmp[ABSPATHLEN+1];

  maxlen = (maxlen < ABSPATHLEN ? maxlen : ABSPATHLEN);

  key = (struct nk_key *)(hdesc->buffer + nkofs);
  
  if (key->id != 0x6b6e) {
    printf("get_abs_path: Not a 'nk' node!\n");
    return(0);
  }

  if (key->type == KEY_ROOT) {   /* We're at the root */
    return(strlen(path));
  }

  strncpy(tmp,path,ABSPATHLEN-1);

  if ( (strlen(path) + key->len_name) >= maxlen-6) {
    snprintf(path,maxlen,"(...)%s",tmp);
    return(strlen(path));   /* Stop trace when string exhausted */
  }
  *path = '\\';
  memcpy(path+1,key->keyname,key->len_name);
  strncpy(path+key->len_name+1,tmp,maxlen);
  return(get_abs_path(hdesc, key->ofs_parent+0x1004, path, maxlen)); /* go back one more */
}


/* Value index table lookup
 * hdesc - hive as usual
 * vlistofs - offset of table
 * name - value name to look for
 * returns index into table or -1 if err
 */

int vlist_find(struct hive *hdesc, int vlistofs, int numval, char *name)
{
  struct vk_key *vkkey;
  int i,vkofs;
  long *vlistkey;

  vlistkey = (long *)(hdesc->buffer + vlistofs);

  for (i = 0; i < numval; i++) {
    vkofs = vlistkey[i] + 0x1004;
    vkkey = (struct vk_key *)(hdesc->buffer + vkofs);
    if (vkkey->len_name == 0 && *name == '@') { /* @ is alias for nameless value */
      return(i);
    }
    if (!strncmp(name, vkkey->keyname, strlen(name))) { /* name match? */
      return(i);
    }
  }
  return(-1);

}

/* Recursevely follow 'nk'-nodes based on a path-string,
 * returning offset of last 'nk' or 'vk'
 * vofs - offset to start node
 * path - null-terminated pathname (relative to vofs, \ is separator)
 * type - type to return 0=nk 1=vk
 * return: offset to nk or vk (or NULL if not found)
 */

int trav_path(struct hive *hdesc, int vofs, char *path, int type)
{
  struct nk_key *key, *newnkkey;
  struct lf_key *lfkey;
  struct li_key *likey;
  struct ri_key *rikey;

  long *vlistkey;
  int newnkofs, plen, i, lfofs, vlistofs, adjust, r, ricnt, subs;
  char *buf;
  char part[ABSPATHLEN+1];
  char *partptr;

  buf = hdesc->buffer;

  if (*path == '\\' && *(path+1) != '\\') {      /* Start from root if path starts with \ */
    path++;
    vofs = hdesc->rootofs+4;
  }

  key = (struct nk_key *)(buf + vofs);
  /*  printf("check of nk at offset: 0x%0x\n",vofs); */

  if (key->id != 0x6b6e) {
    printf("trav_path: Error: Not a 'nk' node!\n");
    return(0);
  }

  /* Find \ delimiter or end of string, copying to name part buffer as we go,
     rewriting double \\s */
  partptr = part;
  for(plen = 0; path[plen] && (path[plen] != '\\' || path[plen+1] == '\\'); plen++) {
    if (path[plen] == '\\' && path[plen+1] == '\\') plen++; /* Skip one if double */
    *partptr++ = path[plen];
  }
  *partptr = '\0';

  /*  printf("Name component: <%s>\n",part); */

  adjust = (path[plen] == '\\' ) ? 1 : 0;
  /*  printf("Checking for <%s> with len %d\n",path,plen); */
  if (!plen) return(vofs-4);     /* Path has no lenght - we're there! */
  if ( (plen == 1) && (*path == '.')) {     /* Handle '.' current dir */
    return(trav_path(hdesc,vofs,path+plen+adjust,type));
  }
  if ( (plen == 2) && !strncmp("..",path,2) ) { /* Get parent key */
    newnkofs = key->ofs_parent + 0x1004;
    /* Return parent (or only root if at the root) */
    return(trav_path(hdesc, (key->type == KEY_ROOT ? vofs : newnkofs), path+plen+adjust, type));
  }

  /* at last name of path, and we want vk, and the nk has values */
  if (!path[plen] && type == 1 && key->no_values) {   
    /*    printf("VK namematch for <%s>\n",part); */
    vlistofs = key->ofs_vallist + 0x1004;
    vlistkey = (long *)(buf + vlistofs);
    i = vlist_find(hdesc, vlistofs, key->no_values, part);
    if (i != -1) {
      return(vlistkey[i] + 0x1000);
    }
  }

  if (key->no_subkeys > 0) {    /* If it has subkeys, loop through the hash */
    lfofs = key->ofs_lf + 0x1004;    /* lf (hash) record */
    lfkey = (struct lf_key *)(buf + lfofs);

    if (lfkey->id == 0x6972) { /* ri struct need special parsing */
      /* Prime loop state */

      rikey = (struct ri_key *)lfkey;
      ricnt = rikey->no_lis;
      r = 0;
      likey = (struct li_key *)( hdesc->buffer + rikey->hash[r].ofs_li + 0x1004 ) ;
      subs = likey->no_keys;
    } else {
      if (lfkey->id == 0x696c) { /* li? */
	likey = (struct li_key *)(buf + lfofs);
      } else {
	likey = NULL;
      }
      ricnt = 0; r = 0; subs = key->no_subkeys;
    }

    do {
      for(i = 0; i < subs; i++) {
	if (likey) newnkofs = likey->hash[i].ofs_nk + 0x1004;
	else newnkofs = lfkey->hash[i].ofs_nk + 0x1004;
	newnkkey = (struct nk_key *)(buf + newnkofs);
	if (newnkkey->id != 0x6b6e) {
	  printf("ERROR: not 'nk' node! (strange?)\n");
	} else {
	  if (newnkkey->len_name <= 0) {
	    printf("[No name]\n");
	  } else {
	    if (!strncmp(part,newnkkey->keyname,plen)) {
	      /*	    printf("Key at 0x%0x matches! recursing!\n",newnkofs); */
	      return(trav_path(hdesc, newnkofs, path+plen+adjust, type));
	    }
	  }
	} /* if id OK */
      } /* hash loop */
      r++;
      if (ricnt && r < ricnt) {
	newnkofs = rikey->hash[r].ofs_li;
	likey = (struct li_key *)( hdesc->buffer + newnkofs + 0x1004 ) ;
	subs = likey->no_keys;
      }
    } while (r < ricnt && ricnt);

  } /* if subkeys */
  /* Not found */
  return(0);
}

/* ls - list a 'nk' nodes subkeys and values
 * vofs - offset to start of data (skipping block linkage)
 * type - 0 = full, 1 = keys only. 2 = values only
 */
void nk_ls(struct hive *hdesc, char *path, int vofs, int type)
{
  struct nk_key *key;
  int nkofs;
  struct ex_data ex;
  struct vex_data vex;
  int count = 0, countri = 0;
  

  nkofs = trav_path(hdesc, vofs, path, 0);

  if(!nkofs) {
    printf("nk_ls: Key <%s> not found\n",path);
    abort();
    return;
  }
  nkofs += 4;

  key = (struct nk_key *)(hdesc->buffer + nkofs);
  printf("ls of node at offset 0x%0x\n",nkofs);

  if (key->id != 0x6b6e) {
    printf("Error: Not a 'nk' node!\n");

    debugit(hdesc->buffer,hdesc->size);
    
  }
  
  printf("Node has %ld subkeys and %ld values\n",key->no_subkeys,key->no_values);

  if (key->no_subkeys) {
    printf("offs          key name\n");
    while ((ex_next_n(hdesc, nkofs, &count, &countri, &ex) > 0)) {
      printf("[%6x]   <%s>\n", ex.nkoffs, ex.name);
      FREE(ex.name);
    }
  }
  count = 0;
  if (key->no_values) {
    printf("offs        size      type   value name                    [value if type DWORD]\n");
    while ((ex_next_v(hdesc, nkofs, &count, &vex) > 0)) {
      printf("[%6x] %6d  %-16s  <%s>", vex.vkoffs, vex.size,
	     (vex.type < REG_MAX ? val_types[vex.type] : "(unknown)"), vex.name);
      if (vex.type == REG_DWORD) printf(" %*d [0x%x]",25-strlen(vex.name),vex.val , vex.val);
      printf("\n");
      FREE(vex.name);
    }
  }
}

/* Get the type of a value */
int get_val_type(struct hive *hdesc, int vofs, char *path)
{
  struct vk_key *vkkey;
  int vkofs;

  vkofs = trav_path(hdesc, vofs,path,1);
  if (!vkofs) {
    return -1;
  }
  vkofs +=4;
  vkkey = (struct vk_key *)(hdesc->buffer + vkofs);
#if 0
  if (vkkey->len_data & 0x80000000) return(REG_DWORD); /* Special case of INLINE storage */
#endif
  return(vkkey->val_type);
}


/* Get len of a value, given current key + path */
int get_val_len(struct hive *hdesc, int vofs, char *path)
{
  struct vk_key *vkkey;
  int vkofs;
  int len;

  vkofs = trav_path(hdesc, vofs,path,1);
  if (!vkofs) {
    return -1;
  }
  vkofs +=4;
  vkkey = (struct vk_key *)(hdesc->buffer + vkofs);

  len = vkkey->len_data & 0x7fffffff;

  if ( vkkey->len_data == 0x80000000 ) {  /* Special inline case, return size of 4 (dword) */
    len = 4;
  }

  return(len);
}

/* Get void-pointer to value-data, also if inline.
 * If val_type != 0 a check for correct value type is done
 * Caller must keep track of value's length (call function above to get it)
 */
void *get_val_data(struct hive *hdesc, int vofs, char *path, int val_type)
{
  struct vk_key *vkkey;
  int vkofs;

  vkofs = trav_path(hdesc,vofs,path,1);
  if (!vkofs) {
    return NULL;
  }
  vkofs +=4;
  vkkey = (struct vk_key *)(hdesc->buffer + vkofs);


  if (vkkey->len_data == 0) return NULL;
  if (vkkey->len_data == 0x80000000) {  /* Special inline case (len = 0x80000000) */
    return(&vkkey->val_type); /* Data (4 bytes?) in type field */
  }    

  if (val_type && vkkey->val_type && (vkkey->val_type) != val_type) {
    printf("Value <%s> is not of correct type!\n",path);
    return NULL;
  }

  /* Negative len is inline, return ptr to offset-field which in
   * this case contains the data itself
   */
  if (vkkey->len_data & 0x80000000) return(&vkkey->ofs_data);
  /* Normal return, return data pointer */
  return(hdesc->buffer + vkkey->ofs_data + 0x1004);
}


/* Get and copy key data (if any) to buffer
 * if kv==NULL will allocate needed return struct & buffer
 * else will use buffer allocated for it (if it fits)
 * return len+data or NULL if not found (or other error)
 * NOTE: caller must deallocate buffer! a simple free(keyval) will suffice.
 */
struct keyval *get_val2buf(struct hive *hdesc, struct keyval *kv,
			    int vofs, char *path, int type )
{
  int l;
  struct keyval *kr;
  void *keydataptr;

  l = get_val_len(hdesc, vofs, path);
  if (l == -1) return(NULL);  /* error */
  if (kv && (kv->len < l)) return(NULL); /* Check for overflow of supplied buffer */

  keydataptr = get_val_data(hdesc, vofs, path, type);
  /*  if (!keydataptr) return(NULL); error */

  /* Allocate space for data + header, or use supplied buffer */
  if (kv) {
    kr = kv;
  } else {
    ALLOC(kr,1,l+sizeof(int)+4);
  }

  kr->len = l;
  memcpy(&(kr->data), keydataptr, l);

  return(kr);
}

/* DWORDs are so common that I make a small function to get it easily */

int get_dword(struct hive *hdesc, int vofs, char *path)
{
  struct keyval *v;
  int dword;

  v = get_val2buf(hdesc, NULL, vofs, path, REG_DWORD);
  if (!v) return(-1); /* well... -1 COULD BE THE STORED VALUE TOO */

  dword = (int)v->data;

  FREE(v);

  return(dword);
  
}


/* Free actual data of a value, and update value descriptor
 * hdesc - hive
 * vofs  - current key
 * path  - path to value
 * we return offset of vk
 */

int free_val_data(struct hive *hdesc, int vofs, char *path)
{
  struct vk_key *vkkey;
  int vkofs, inl;

  vkofs = trav_path(hdesc,vofs,path,1);
  if (!vkofs) {
    return 0;
  }
  vkofs +=4;
  vkkey = (struct vk_key *)(hdesc->buffer + vkofs);

  inl = (vkkey->len_data & 0x80000000);

  if (!inl) {
    free_block(hdesc, vkkey->ofs_data + 0x1000);
  }
  vkkey->len_data = 0;
  vkkey->ofs_data = 0;

  return(vkofs);

}

/* Allocate data for value, realloc if it already contains stuff
 * hdesc - hive
 * vofs  - current key
 * path  - path to value
 * size  - size of data
 * Returns: 0 - error, >0 pointer to actual dataspace
 */

int alloc_val_data(struct hive *hdesc, int vofs, char *path, int size)
{
  struct vk_key *vkkey;
  int vkofs, len;
  int datablk;

  vkofs = trav_path(hdesc,vofs,path,1);
  if (!vkofs) {
    return (0);
  }

  vkofs +=4;
  vkkey = (struct vk_key *)(hdesc->buffer + vkofs);

  /* Allocate space for new data */
  datablk = alloc_block(hdesc, vkofs, size);
  if (!datablk) return(0);

  len = vkkey->len_data & 0x7fffffff;

  /* Then we dealloc if something was there before */
  if (len) free_val_data(hdesc,vofs,path);

  /* Link in new datablock */
  vkkey->ofs_data = datablk - 0x1000;
  vkkey->len_data = size;

  return(datablk + 4);
}


/* Add a value to a key.
 * Just add the metadata (empty value), to put data into it, use
 * put_buf2val afterwards
 * hdesc - hive
 * nkofs - current key
 * name  - name of value
 * type  - type of value
 * returns: 0 err, >0 offset to value metadata
 */

struct vk_key *add_value(struct hive *hdesc, int nkofs, char *name, int type)
{
  struct nk_key *nk;
  int oldvlist = 0, newvlist, newvkofs;
  struct vk_key *newvkkey;

  if (!name || !*name) return(NULL);

  nk = (struct nk_key *)(hdesc->buffer + nkofs);
  if (nk->id != 0x6b6e) {
    printf("add_value: Key pointer not to 'nk' node!\n");
    return(NULL);
  }

  if (trav_path(hdesc, nkofs, name, 1)) {
    printf("add_value: value %s already exists\n",name);
    return(NULL);
  }
 
  if (nk->no_values) oldvlist = nk->ofs_vallist;

  newvlist = alloc_block(hdesc, nkofs, nk->no_values * 4 + 4);
  if (!newvlist) {
    printf("add_value: failed to allocate new value list!\n");
    return(NULL);
  }
  if (oldvlist) {   /* Copy old data if any */
    memcpy(hdesc->buffer + newvlist + 4, hdesc->buffer + oldvlist + 0x1004, nk->no_values * 4 + 4);
  }

  /* Allocate value descriptor including its name */
  newvkofs = alloc_block(hdesc, newvlist, sizeof(struct vk_key) + strlen(name));
  if (!newvkofs) {
    printf("add_value: failed to allocate value descriptor\n");
    free_block(hdesc, newvlist);
    return(NULL);
  }

  /* Success, now fill in the metadata */

  newvkkey = (struct vk_key *)(hdesc->buffer + newvkofs + 4);

  /* Add pointer in value list */
  *(int *)(hdesc->buffer + newvlist + 4 + (nk->no_values * 4)) = newvkofs - 0x1000;

  /* Fill in vk struct */
  newvkkey->id = 0x6b76;
  newvkkey->len_name = strlen(name);
  if (type == REG_DWORD || type == REG_DWORD_BIG_ENDIAN) {
    newvkkey->len_data = 0x80000004;  /* Prime the DWORD inline stuff */
  } else {
    newvkkey->len_data = 0x00000000;
  }
  newvkkey->ofs_data = 0;
  newvkkey->val_type = type;
  newvkkey->flag     = 1;   /* Don't really know what this is */
  newvkkey->dummy1   = 0;
  strcpy((char *)&newvkkey->keyname, name);  /* And copy name */

  /* Finally update the key and free the old valuelist */
  nk->no_values++;
  nk->ofs_vallist = newvlist - 0x1000;
  if (oldvlist) free_block(hdesc,oldvlist + 0x1000);

  return(newvkkey);

}

/* Remove a vk-struct incl dataspace if any
 * Mostly for use by higher level stuff
 * hdesc - hive
 * vkofs - offset to vk
 */

void del_vk(struct hive *hdesc, int vkofs)
{
  struct vk_key *vk;

  vk = (struct vk_key *)(hdesc->buffer + vkofs);
  if (vk->id != 0x6b76) {
    printf("del_vk: Key pointer not to 'vk' node!\n");
    return;
  }
  
  if ( !(vk->len_data & 0x80000000) && vk->ofs_data) {
    free_block(hdesc, vk->ofs_data + 0x1000);
  }

  free_block(hdesc, vkofs - 4);
}

/* Delete all values from key (used in recursive delete)
 * hdesc - yer usual hive
 * nkofs - current keyoffset
 */

void del_allvalues(struct hive *hdesc, int nkofs)
{
  int vlistofs, o, vkofs;
  long *vlistkey;
  struct nk_key *nk;

  nk = (struct nk_key *)(hdesc->buffer + nkofs);
  if (nk->id != 0x6b6e) {
    printf("del_allvalues: Key pointer not to 'nk' node!\n");
    return;
  }

  if (!nk->no_values) {
    printf("del_avalues: Key has no values!\n");
    return;
  }

  vlistofs = nk->ofs_vallist + 0x1004;
  vlistkey = (long *)(hdesc->buffer + vlistofs);

  /* Loop through index and delete all vk's */
  for (o = 0; o < nk->no_values; o++) {
    vkofs = vlistkey[o] + 0x1004;
    del_vk(hdesc, vkofs);
  }

  /* Then zap the index, and update nk */
  free_block(hdesc, vlistofs-4);
  nk->ofs_vallist = -1;
  nk->no_values = 0;
}


/* Delete single value from key
 * hdesc - yer usual hive
 * nkofs - current keyoffset
 * name  - name of value to delete
 * returns: 0 - ok, 1 - failed
 */

int del_value(struct hive *hdesc, int nkofs, char *name)
{
  int vlistofs, slot, o, n, vkofs, newlistofs;
  long *vlistkey, *tmplist, *newlistkey;
  struct nk_key *nk;

  if (!name || !*name) return(1);

  nk = (struct nk_key *)(hdesc->buffer + nkofs);
  if (nk->id != 0x6b6e) {
    printf("del_value: Key pointer not to 'nk' node!\n");
    return(1);
  }

  if (!nk->no_values) {
    printf("del_value: Key has no values!\n");
    return(1);
  }

  vlistofs = nk->ofs_vallist + 0x1004;
  vlistkey = (long *)(hdesc->buffer + vlistofs);

  slot = vlist_find(hdesc, vlistofs, nk->no_values, name);

  if (slot == -1) {
    printf("del_value: value %s not found!\n",name);
    return(1);
  }

  /* Delete vk and data */
  vkofs = vlistkey[slot] + 0x1004;
  del_vk(hdesc, vkofs);

  /* Copy out old index list */
  CREATE(tmplist,long,nk->no_values);
  memcpy(tmplist, vlistkey, nk->no_values * sizeof(long));

  free_block(hdesc,vlistofs-4);  /* Get rid of old list */

  nk->no_values--;

  if (nk->no_values) {
    newlistofs = alloc_block(hdesc, vlistofs, nk->no_values * sizeof(long));
    if (!newlistofs) {
      printf("del_value: FATAL: Was not able to alloc new index list\n");
      abort();
    }
    /* Now copy over, omitting deleted entry */
    newlistkey = (long *)(hdesc->buffer + newlistofs + 4);
    for (n = 0, o = 0; o < nk->no_values+1; o++, n++) {
      if (o == slot) o++;
      newlistkey[n] = tmplist[o];
    }
    nk->ofs_vallist = newlistofs - 0x1000;
  } else {
    nk->ofs_vallist = -1;
  }
  return(0);
}

/* Add a subkey to a key
 * hdesc - usual..
 * nkofs - offset of current nk
 * name  - name of key to add
 * return: ptr to new keystruct, or NULL
 */

struct nk_key *add_key(struct hive *hdesc, int nkofs, char *name)
{

  int slot = 0, newlfofs = 0, oldlfofs = 0, o, n, i, onkofs, newnkofs, cmp;
  struct lf_key *newlf, *oldlf;
  struct nk_key *key, *newnk, *onk;
  long hash;

  key = (struct nk_key *)(hdesc->buffer + nkofs);

  if (key->id != 0x6b6e) {
    printf("add_key: current ptr not 'nk'\n");
    return(NULL);
  }

  slot = -1;
  if (key->no_subkeys) {   /* It already has subkeys */
    
    oldlfofs = key->ofs_lf;
    oldlf = (struct lf_key *)(hdesc->buffer + oldlfofs + 0x1004);
    if (oldlf->id != 0x666c && oldlf->id != 0x686c) {
      printf("add_key: index other than 'lf' or 'lh' not supported yet. 0x%04x\n",oldlf->id);
      return(NULL);
    }

    ALLOC(newlf, 8 + 8*oldlf->no_keys + 8, 1);
    newlf->no_keys = oldlf->no_keys + 1;
    newlf->id = oldlf->id;

    /* Now copy old, checking where to insert (alphabetically) */
    for (o = 0, n = 0; o < oldlf->no_keys; o++,n++) {
      onkofs = oldlf->hash[o].ofs_nk;
      onk = (struct nk_key *)(onkofs + hdesc->buffer + 0x1004);
      if (slot == -1) {
	cmp = strncasecmp(name, onk->keyname, onk->len_name);
	if (!cmp) {
	  printf("add_key: key %s already exists!\n",name);
	  FREE(newlf);
	  return(NULL);
	}
	if ( cmp < 0) {
	  slot = o;
	  n++;
	}
      }
      newlf->hash[n].ofs_nk = oldlf->hash[o].ofs_nk;
      newlf->hash[n].name[0] = oldlf->hash[o].name[0];
      newlf->hash[n].name[1] = oldlf->hash[o].name[1];
      newlf->hash[n].name[2] = oldlf->hash[o].name[2];
      newlf->hash[n].name[3] = oldlf->hash[o].name[3];
    }
    if (slot == -1) slot = oldlf->no_keys;
  } else {
    ALLOC(newlf, 8 + 8, 1);
    newlf->no_keys = 1;
    newlf->id = 0x666c;  
  }

  /* Make and fill in new nk */
  newnkofs = alloc_block(hdesc, nkofs, sizeof(struct nk_key) + strlen(name));
  if (!newnkofs) {
    printf("add_key: unable to allocate space for new key descriptor for %s!\n",name);
    FREE(newlf);
    return(NULL);
  }
  newnk = (struct nk_key *)(hdesc->buffer + newnkofs + 4);
  
  newnk->id            = 0x6b6e;
  newnk->type          = KEY_NORMAL;
  newnk->ofs_parent    = nkofs - 0x1004;
  newnk->no_subkeys    = 0;
  newnk->ofs_lf        = 0;
  newnk->no_values     = 0;
  newnk->ofs_vallist   = -1;
  newnk->ofs_sk        = key->ofs_sk; /* Get parents for now. 0 or -1 here crashes XP */
  newnk->ofs_classnam  = -1;
  newnk->len_name      = strlen(name);
  newnk->len_classnam  = 0;
  strncpy(newnk->keyname, name, strlen(name));
  
  /* And put its offset into parents index list */
  newlf->hash[slot].ofs_nk = newnkofs - 0x1000;
  if (newlf->id == 0x666c) {        /* lf hash */
    newlf->hash[slot].name[0] = 0;
    newlf->hash[slot].name[1] = 0;
    newlf->hash[slot].name[2] = 0;
    newlf->hash[slot].name[3] = 0;
    strncpy(newlf->hash[n].name, name, 4);
  } else if (newlf->id == 0x686c) {  /* lh. XP uses this. hashes whole name */
      for (i = 0,hash = 0; i < strlen(name); i++) {
	hash *= 37;
	hash += toupper(name[i]);
      }
      newlf->lh_hash[slot].hash = hash;
  }

  /* Allocate space for our new lf list and copy it into reg */
  newlfofs = alloc_block(hdesc, nkofs, 8 + 8*newlf->no_keys);
  if (!newlfofs) {
    printf("add_key: unable to allocate space for new key descriptor for %s!\n",name);
    FREE(newlf);
    free_block(hdesc,newnkofs);
    return(NULL);
  }
  memcpy(hdesc->buffer + newlfofs + 4, newlf, 8 + 8*newlf->no_keys);

  /* Update parent, and free old lf list */
  key->no_subkeys++;
  key->ofs_lf = newlfofs - 0x1000;
  if (oldlfofs) free_block(hdesc,oldlfofs + 0x1000);

  FREE(newlf);
  return(newnk);


}

/* Delete a subkey from a key
 * hdesc - usual..
 * nkofs - offset of current nk
 * name  - name of key to delete
 * return: 1 - err, 0 - ok
 */

int del_key(struct hive *hdesc, int nkofs, char *name)
{

  int slot = 0, newlfofs = 0, oldlfofs = 0, o, n, onkofs,  delnkofs;
  struct lf_key *newlf, *oldlf;
  struct nk_key *key, *onk, *delnk;

  key = (struct nk_key *)(hdesc->buffer + nkofs);

  if (key->id != 0x6b6e) {
    printf("add_key: current ptr not nk\n");
    return(1);
  }

  slot = -1;
  if (!key->no_subkeys) {
    printf("del_key: key has no subkeys!\n");
    return(1);
  }

  oldlfofs = key->ofs_lf;
  oldlf = (struct lf_key *)(hdesc->buffer + oldlfofs + 0x1004);
  if (oldlf->id != 0x666c && oldlf->id != 0x686c) {
    printf("del_key: index other than 'lf' or 'lh' not supported yet. 0x%04x\n",oldlf->id);
    return(1);
  }

  ALLOC(newlf, 8 + 8*oldlf->no_keys - 8, 1);
  newlf->no_keys = oldlf->no_keys - 1;
  newlf->id = oldlf->id;

  /* Now copy old, checking where to delete */
  for (o = 0, n = 0; o < oldlf->no_keys; o++,n++) {
    onkofs = oldlf->hash[o].ofs_nk;
    onk = (struct nk_key *)(onkofs + hdesc->buffer + 0x1004);
    if (slot == -1 && !strncmp(name, onk->keyname, onk->len_name)) {
        slot = o;
	delnkofs = onkofs; delnk = onk;
	o++;
    }
    newlf->hash[n].ofs_nk = oldlf->hash[o].ofs_nk;
    newlf->hash[n].name[0] = oldlf->hash[o].name[0];
    newlf->hash[n].name[1] = oldlf->hash[o].name[1];
    newlf->hash[n].name[2] = oldlf->hash[o].name[2];
    newlf->hash[n].name[3] = oldlf->hash[o].name[3];
  }
  if (slot == -1) {
    printf("del_key: subkey %s not found!\n",name);
    FREE(newlf);
    return(1);
  }

  if (delnk->no_values || delnk->no_subkeys) {
    printf("del_key: subkey %s has subkeys or values. Not deleted.\n",name);
    FREE(newlf);
    return(1);
  }

  /* Allocate space for our new lf list and copy it into reg */
  if (newlf->no_keys) {
    newlfofs = alloc_block(hdesc, nkofs, 8 + 8*newlf->no_keys);
    if (!newlfofs) {
      printf("del_key: unable to allocate space for new key descriptor for %s! Not deleted\n",name);
      FREE(newlf);
      return(1);
    }
    memcpy(hdesc->buffer + newlfofs + 4, newlf, 8 + 8*newlf->no_keys);
  } else {  /* Last deleted, will throw away index */
    newlfofs = -1;
  }

  /* Now it's safe to zap the nk */
  free_block(hdesc, delnkofs + 0x1000);

  /* Update parent */
  key->no_subkeys--;
  key->ofs_lf = newlfofs - 0x1000;

  FREE(newlf);
  return(0);

}



/* Write to registry value.
 * If same size as existing, copy back in place to avoid changing too much
 * otherwise allocate new dataspace, then free the old
 * Thus enough space to hold both new and old data is needed
 * Pass inn buffer with data len as first DWORD (as routines above)
 * returns: 0 - error, len - OK (len of data)
 */

int put_buf2val(struct hive *hdesc, struct keyval *kv,
			    int vofs, char *path, int type )
{
  int l;
  void *keydataptr;

  if (!kv) return(0);
  l = get_val_len(hdesc, vofs, path);
  if (l == -1) return(0);  /* error */
  if (kv->len != l) {  /* Realloc data block if not same size as existing */
    if (!alloc_val_data(hdesc, vofs, path, kv->len)) {
      printf("put_buf2val: %s : alloc_val_data failed!\n",path);
      return(0);
    }
  }

  keydataptr = get_val_data(hdesc, vofs, path, type);
  if (!keydataptr) return(0); /* error */

  memcpy(keydataptr, &kv->data, kv->len);

  hdesc->state |= HMODE_DIRTY;

  return(kv->len);
}

/* And, yer basic DWORD write */

int put_dword(struct hive *hdesc, int vofs, char *path, int dword)
{
  struct keyval *kr;
  int r;

  ALLOC(kr,1,sizeof(int)+sizeof(int));
  
  kr->len = sizeof(int);
  (int)kr->data = dword;

  r = put_buf2val(hdesc, kr, vofs, path, REG_DWORD);

  FREE(kr);

  return(r);
}


/* ================================================================ */

/* Hive control (load/save/close) etc */

void closeHive(struct hive *hdesc)
{

  printf("closing hive %s\n",hdesc->filename);
  FREE(hdesc->filename);
  FREE(hdesc->buffer);
  FREE(hdesc);

}

/* Write the hive back to disk (only if dirty & not readonly */
int writeHive(struct hive *hdesc)
{
  int len;

  if (hdesc->state & HMODE_RO) return(0);
  if ( !(hdesc->state & HMODE_DIRTY)) return(0);

  if ( !(hdesc->state & HMODE_OPEN)) { /* File has been closed */
    if (!(hdesc->filedesc = open(hdesc->filename,O_RDWR))) {
      fprintf(stderr,"writeHive: open(%s) failed: %s, FILE NOT WRITTEN!\n",hdesc->filename,strerror(errno));
      return(1);
    }
    hdesc->state |= HMODE_OPEN;
  }  
  /* Seek back to begginning of file (in case it's already open) */
  lseek(hdesc->filedesc, 0, SEEK_SET);

  len = write(hdesc->filedesc, hdesc->buffer, hdesc->size);
  if (len != hdesc->size) {
    fprintf(stderr,"writeHive: write of %s failed: %s.\n",hdesc->filename,strerror(errno));
    return(1);
  }

  hdesc->state &= (~HMODE_DIRTY);
  return(0);
}

struct hive *openHive(char *filename, int mode)
{

  struct hive *hdesc;
  int fmode,r,vofs;
  struct stat sbuf;
  unsigned long pofs;
  /* off_t l; */
  char *c;
  struct hbin_page *p;
  struct regf_header *hdr;
  int verbose = (mode & HMODE_VERBOSE);

  CREATE(hdesc,struct hive,1);

  hdesc->filename = str_dup(filename);
  hdesc->state = 0;
  hdesc->size = 0;
  hdesc->buffer = NULL;

  if ( (mode & HMODE_RO) ) {
    fmode = O_RDONLY;
  } else {
    fmode = O_RDWR;
  }
  hdesc->filedesc = open(hdesc->filename,fmode);
  if (!(hdesc->filedesc)) {
    fprintf(stderr,"openHive(%s) failed: %s, trying read-only\n",hdesc->filename,strerror(errno));
    fmode = O_RDONLY;
    mode |= HMODE_RO;
    hdesc->filedesc = open(hdesc->filename,fmode);
    if (!(hdesc->filedesc)) {
      fprintf(stderr,"openHive(%s) in fallback RO-mode failed: %s\n",hdesc->filename,strerror(errno));
      closeHive(hdesc);
      return(NULL);
    }
  }


  if ( fstat(hdesc->filedesc,&sbuf) ) {
    perror("stat()");
    exit(1);
  }

  hdesc->size = sbuf.st_size;
  hdesc->state = mode | HMODE_OPEN;
  /*  fprintf(stderr,"hiveOpen(%s) successful\n",hdesc->filename); */
  
  /* Read the whole file */

  ALLOC(hdesc->buffer,1,hdesc->size);

  r = read(hdesc->filedesc,hdesc->buffer,hdesc->size);
  if (r < hdesc->size) {
    fprintf(stderr,"Could not read file, got %d bytes while expecting %d\n",
	    r, hdesc->size);
    closeHive(hdesc);
    return(NULL);
  }

  /* Now run through file, tallying all pages */
  /* NOTE/KLUDGE: Assume first page starts at offset 0x1000 */

   pofs = 0x1000;

   hdr = (struct regf_header *)hdesc->buffer;
   if (hdr->id != 0x66676572) {
     printf("openHive(%s): File does not seem to be a registry hive!\n",filename);
     return(hdesc);
   }
   //   printf("Hive's name (from header): <");
   //   for (c = hdr->name; *c && (c < hdr->name + 64); c += 2) putchar(*c);

   hdesc->rootofs = hdr->ofs_rootkey + 0x1000;
   //   printf(">\nROOT KEY at offset: 0x%06x\n",hdesc->rootofs);

   while (pofs < hdesc->size) {
          if (verbose) hexdump(hdesc->buffer,pofs,pofs+0x20,1);
     p = (struct hbin_page *)(hdesc->buffer + pofs);
     if (p->id != 0x6E696268) {
       fprintf(stderr, "Page at 0x%lx is not 'hbin', assuming file contains garbage at end",pofs);
       break;
     }
     hdesc->pages++;
     if (verbose) printf("\n###### Page at 0x%0lx has size 0x%0lx, next at 0x%0lx ######\n",pofs,p->len_page,p->ofs_next);

     if (p->ofs_next == 0) {
       if (verbose) printf("openhive debug: bailing out.. pagesize zero!\n");
       return(hdesc);
     }
#if 0
     if (p->len_page != p->ofs_next) {
       if (verbose) printf("openhive debug: len & ofs not same. HASTA!\n");
       exit(0);
     }
#endif


     vofs = pofs + 0x20; /* Skip page header */
#if 1
     while (vofs-pofs < p->ofs_next) {
       vofs += parse_block(hdesc,vofs,verbose);

     }
#endif
     pofs += p->ofs_next;
   }
   //   printf("\nFile size %d [%x] bytes, containing %d pages (+ 1 headerpage)\n",hdesc->size,hdesc->size, hdesc->pages);
   //  printf("Used for data: %d/%d blocks/bytes, unused: %d/%d blocks/bytes.\n",
   //	  hdesc->useblk,hdesc->usetot,hdesc->unuseblk,hdesc->unusetot);
  

  return(hdesc);

}

