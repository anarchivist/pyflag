/*
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.75 Date: Sat Feb 12 14:00:04 EST 2005$
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
#include "index.h"
#include <stdio.h>
#include "except.h"
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>
#include <errno.h>

static int verbose=10;

inline int comparison(char x, char y) {
  return(!strncasecmp(&x,&y,1));
  //return x==tolower(y);
  //return x==y;
};

void debug(int level,const char *message, ...)
{
	va_list ap;
	if(verbose<level) return;

	va_start(ap, message);
	vfprintf(stderr,message, ap);
	va_end(ap);
};

#define BUFFER 1000
#define FILEBUFFER 10000000
#define max(x,y) (x>y ? x: y)

//The size of the heap mmaped at the same time (in pages)
static int heap_mapped_length=100000;
//static int heap_file_offset=0;

/* Write the index file header and return the total number of bytes occupied by the header. */
int write_index_header(int fd) 
{
  int size=heap_mapped_length;
  char *buf=(char *)malloc(size);

  //Copy the file magic to the index:
  write(fd,index_magic,strlen(index_magic));

  //This fills the file with the initial root node
  memset(buf,0,size);
  ((struct idx_node *)buf)->c='*';

  if(write(fd,buf,size)<0)
    RAISE(E_IOERROR,NULL,"Could not write file header");

  free(buf);
  return(strlen(index_magic));
};

/* Called to initialise our heap structures */
void init_heap(struct index_file *idx) 
{
  int page_size=getpagesize();

  //Is heap_mapped_length a multiple of page_size? if not we round it...
  if(((int)(heap_mapped_length/page_size))*page_size != heap_mapped_length) {
    heap_mapped_length=((int)(heap_mapped_length/page_size))*page_size;
  };

  idx->heap = (char *)mmap(0, heap_mapped_length,
          PROT_READ | PROT_WRITE , MAP_SHARED , idx->heap_fd
          , idx->heap_file_offset);

  if(idx->heap==MAP_FAILED) 
    RAISE(E_NOMEMORY,NULL,"Unable to mmap file: %s",strerror(errno));
  
  idx->heap_size=heap_mapped_length;
};

void free_index(struct index_file *idx) 
{
  munmap(idx->heap,idx->heap_size);
  close(idx->heap_fd);
  idx->heap_size=0;
  idx->heap=NULL;
};

/*Implements our own malloc giving a small chunk off our own heap - if
  our heap needs to grow, this will take care of it */
heap_ptr idx_malloc(struct index_file *idx,int size) 
{
  char *buffer;
  heap_ptr temp=idx->end_of_heap_ptr;

  idx->end_of_heap_ptr+=size;

  //Do we fit in the currently allocated chunk?
  if(idx->end_of_heap_ptr > idx->heap_size) {
    idx->heap_size+=heap_mapped_length;
    //    fprintf(stderr,"Will try to grow file to %lu\n",idx->heap_size);

    //We need some quick memory for writing some zeros to the file
    buffer=(char *)malloc(heap_mapped_length);
    if(!buffer) RAISE(E_IOERROR,NULL,"Unable to Malloc");

    memset(buffer,0,heap_mapped_length);
    if(write(idx->heap_fd,buffer,heap_mapped_length)<heap_mapped_length) {
      RAISE(E_IOERROR,NULL,"Unable to grow index file: %s",strerror(errno)); 
    };
    
    free(buffer);

    //Now remap the segment:
    munmap(idx->heap,idx->heap_size-heap_mapped_length);

    idx->heap=(char *)mmap(0,idx->heap_size ,
        PROT_READ | PROT_WRITE , MAP_SHARED ,
        idx->heap_fd , idx->heap_file_offset);

    if(idx->heap==MAP_FAILED) 
      RAISE(E_NOMEMORY,NULL,"Unable to mmap file: %s",strerror(errno));
  };
  return(temp);
};

/* Assigns a new node structure on our heap. Note that the real
   address in memory must be gotten by using absolute_node(heap_ptr)

   NOTE: This function may invalidate all memory pointers because it
   reallocates our private heap. There is a chance that out new heap
   is reallocated to a new location. Callers of these functions must
   ensure they re-get the memory pointers by calling absolute_node
   after calling the new_xxx functions

*/
node_ptr new_node(struct index_file *idx) 
{
  return(idx_malloc(idx,sizeof(struct idx_node)));
};

offlist_ptr new_offset_list(struct index_file *idx) 
{
  return(idx_malloc(idx,sizeof(struct offset_list)));
};

/*
   Creates a new index structure, and reallocates the heap. Since our
   index must live on disk, we create the file immediately.
*/
struct index_file *new_index(char *filename) 
{
  struct index_file *idx;

  //Fill in the global index structure:
  idx=(struct index_file *)calloc(1,sizeof(struct index_file));
  idx->filename=strdup(filename);

  //Index needs to be created
  idx->heap_fd=open(idx->filename,O_RDWR | O_CREAT | O_TRUNC,
		    S_IRWXU);
    
  if(idx->heap_fd<0) 
    RAISE(E_IOERROR,NULL,"Cant open file %s for writing",filename);

  //Write the initial header on the file, and create an initial root node:
  idx->root=write_index_header(idx->heap_fd);
  idx->end_of_heap_ptr=idx->root+sizeof(struct idx_node);
  init_heap(idx);
  return(idx);
};

/* Convert from internal heap offsets to memory pointers */
inline struct idx_node *absolute_node(struct index_file *idx, node_ptr relative) 
{
  return(struct idx_node *)(relative+idx->heap);
};

inline struct offset_list *absolute_offlist(struct index_file *idx, offlist_ptr relative) 
{
  return(struct offset_list *)(relative+idx->heap);
};

/* This function tests the bitmap for the presence of the character c.

   Bitmaps are an optimisation technique that represent the characters
   stored within a list. This way we only need to test the bitmap
   before traversing the entire linked list. The bitmaps are 32 byte
   arrays which are only created for large nodes

   we return: 0 if c is not in bitmap, 1 if it is.
*/
#define BITMAP_SIZE 32
// The size of the peer list where we decide to create a bitmap
#define BITMAP_THRESHOLD 5

inline int test_bitmap(unsigned char *bitmap, unsigned char c) 
{
  unsigned char t = tolower(c);
  unsigned char p = bitmap[t & 0x1f];
  unsigned char bit;

  if(!p) return(0);

  bit=t>>5;
  return(p & (0x1 << bit));
};

/* Set the character c in the bitmap. */
inline void set_bitmap(unsigned char *bitmap,unsigned char c) 
{
  unsigned char t = tolower(c);
  unsigned char *p = bitmap + (t & 0x1f);
  unsigned char bit=t>>5;

  *p |= 0x1 << bit;
};

/* Given a node pointer, search its peers for a node containing c */
static node_ptr find_peer(struct index_file *idx,node_ptr node_ref,
			  const unsigned char *c) 
{
  struct idx_node *node;

  node=absolute_node(idx,node_ref);

  //Does this node have a bitmap?, if so we test it before we bother searching the peerlist for it.
  if(node->bitmap && 
     !test_bitmap((unsigned char *)absolute_node(idx,node->bitmap),*c)) {
    return(0);
  };

  while(1) {
    //Get memory pointers
    node=absolute_node(idx,node_ref);
    if(comparison(node->c,*c)) {
      return(node_ref);
    };

    node_ref=node->peer;
    //We have run out of peers....
    if(!node_ref) return(0);
  };
};

/* Append a new node to the end of the peer list. Returns the node just added */
static node_ptr append_to_peerlist(struct index_file *idx,
		    node_ptr node_ref,unsigned char *c) 
{
  struct idx_node *node,*node2;
  node_ptr temp;
  int count=0;

  temp=new_node(idx);
  
  //Carry the bitmap pointer throughout all peers
  node=absolute_node(idx,node_ref);
  node2=absolute_node(idx,temp);
  node2->bitmap=node->bitmap;
  
  //Get the end of the peers list
  do {
    node=absolute_node(idx,node_ref);
    node_ref=node->peer;
    count++;
  } while(node->peer);

  //Node should point at the end of the list now...
  node->peer=temp;
  node=absolute_node(idx,node->peer);
  //  node->c=tolower(*c);
  node->c=*c;
  return(temp);
};

/* Adds the word pointed to by c to the index at node */
void add_word(struct index_file *idx,unsigned char *c,int length) 
{
  struct idx_node *node;
  node_ptr node_ref=idx->root;
  node_ptr current_node=0;
  offlist_ptr list;
  
  while(length>0) {
    current_node=find_peer(idx,node_ref,c);

    if(current_node) {
      //We found a node in the tree for this letter
      c++;
      length--;
      //Does this node have children?
      node=absolute_node(idx,current_node);

      //Do we need to store another char in the index? if not we use this node.
      if(length==0) {
	node_ref=current_node;
      } else {
           if(!node->child) {
     	//If we dont have children, we create a new child node for it...
     	struct idx_node *child;
     	node_ptr child_ptr=new_node(idx);
     
     	//This is required in case the new_node function relocates the heap
     	node=absolute_node(idx,current_node);
     
     	//The child contains 1 character.
     	node->count=1;
     
     	node->child=child_ptr;
     	child=absolute_node(idx,node->child);
	//     	child->c=tolower(*(c));
	child->c=*c;
           };
           node_ref=node->child;
      };
    } else {
      //We can't find this letter in the peers list, so we need to add the current letter to the peers:
      node=absolute_node(idx,node_ref);
      if(node->count > BITMAP_THRESHOLD ) {
	if(!node->bitmap) {
	  struct idx_node *tmp_node;
	  node_ptr n=node_ref;
	  char *bm;

	  bitmap_ptr temp = (bitmap_ptr)idx_malloc(idx,BITMAP_SIZE);

	  node=absolute_node(idx,node_ref);

	  node->bitmap=temp;

	  bm=(unsigned char *)absolute_node(idx,node->bitmap);

	  //Work through all elements of the list to set the bitmap for all previous elements
	  do {
	    tmp_node=absolute_node(idx,n);
	    set_bitmap(bm,tmp_node->c);
	    n=tmp_node->peer;
	  } while(tmp_node->peer);
	};
	set_bitmap((unsigned char *)absolute_node(idx,node->bitmap),*c);
      };

      node->count++;
      append_to_peerlist(idx,node_ref,c);
      //On the next iteration this will be found
    };
  };

  //Now that the index is built, we need to create an offset for the
  //last node to represent a complete word:
  list=new_offset_list(idx);

  node=absolute_node(idx,current_node);
  node->offsets=list;
  node->last_offset=list;
};

/* Searches index in idx for word. Returns the node pointer of
   word or else return NULL*/
node_ptr find_node(struct index_file *idx, node_ptr root_ptr, 
		   const char *c,int length) 
{
   node_ptr node_ref = root_ptr,current_node=0;
  struct idx_node *node;

  //Test the node we were given
  node=absolute_node(idx,root_ptr);
  if(comparison(node->c,*c)) {
    current_node=root_ptr;
  } else {
    current_node=0;
  };

  while(length>0) {
    if(current_node) {
      c++;
      length--;
      node=absolute_node(idx,current_node);

      if(length>0) {
	node_ref=node->child;
      } else {
	node_ref=current_node;
      };

      if(!node_ref) {
	//There are no children in this node, so we conclude that the
	//word is not in the index.
	return(0);
      };
    } else {
      // Could not find letter in peers, this word is not in the index.
      return(0);
    };
    if(length>0)   {
      current_node=find_peer(idx,node_ref,c);
    } else return(current_node);
  };
  return(current_node);
};

/* Finds the longest match possible from the start of buffer within
   the index. buffer will be advanced to the end of the longest match,
   and the node_ptr for the last character is returned. Note that by
   definition the returned pointer should have an offset list because
   it represents a complete word.
 */
node_ptr is_in_index(struct index_file *idx, char **buffer) 
{
  node_ptr node_ref = idx->root,current_node,saved_node=idx->root;
  struct idx_node *node;
  char *c=*buffer;
  char *saved_c=c;
  
  while(1) {
    current_node=find_peer(idx,node_ref,c);

    if(current_node) {
      c++;
      node=absolute_node(idx,current_node);
      node_ref=node->child;
      if(!node_ref) {
	//There are no children in this node, Hence this node
	//represents the end of a word... We adjust the buffer and
	//return the node.
	*buffer=c;
	return(current_node);
      };

      //If this node has an offsets list, it must represent a complete
      //word. We store it in case we need it later.
      if(node->offsets) {
	saved_node=current_node;
	saved_c=c;
      };
    } else {
      /* 
          Here we are in the middle of a word, and we cant find a
          peer. There are 2 possibilities here: 

	  1) the search buffer is really not in the index,

	  2) There is a shorter match in the index and we have gone
	  too far trying to match a word which is too long. 

           We resolve these problems by consulting the
           saved_node. This parameter stores the last occurance of a
           full word we found in the index.
      */
      if(saved_node==idx->root) {
	//No word found, return Null:
	return(0);
      } else {
	//We return the last word found in the index:
	*buffer=saved_c;
	return(saved_node);
      };
    };
  };
  RAISE(E_GENERIC,NULL,"Should never get here");
  return(0);
};


//A utility function to grow an array of offsets
inline void grow_list(offset_t **l,int *length,offset_t offset) 
{
  offset_t *list=*l;

  if(offset>0xffffffff00000000)
    printf("Offset less than zero at %llu\n",offset);
  list=(offset_t *)realloc(list,((*length)+1)*sizeof(offset_t));
  list[(*length)]=offset;
  (*length)++;
  *l=list;
};

/* Adds all the offsets in the linked list list_ptr, into the array l
   growing it if necessary. Only stores unique offsets */
static void add_offsets_to_array(struct index_file *idx, 
		 offlist_ptr list_ptr,offset_t **l,int *length) 
{
  struct offset_list *temp;
  offset_t *list=*l;

  if(!list_ptr) return;

  temp=absolute_offlist(idx,list_ptr);
  do {
    temp=absolute_offlist(idx, list_ptr);
    if(temp->offset){
      //      printf("Added %llu to list\n",temp->offset);
      grow_list(&list,length,temp->offset-1);
    };
    list_ptr=temp->next;
  } while(temp->next);
  *l=list;
};


/* Recurse over the tree nodes for all nodes which have an offset list
   (i.e. are complete words) and have non null offsets (i.e. have a
   macth somewhere in the buffer). For each of those, we follow their
   offset list and append their offsets to the offset_array.

   The main idea in this algorithm is that if we are searching for a
   short word that just happened to be a substring of a larger word,
   then we must return all the matches of the longer words as well as
   the shorter words. for example, if we search for `index`, we must
   also return all occurances of `indexs` and `indexing`. Note that
   since we always find the longest match during indexing, we should
   never repeat matches.
   
   list is an array of offset_t, if its NULL, this function will
   allocate it - the caller is responsible for freeing the entire
   array later.
 */
static void _find_offsets(struct index_file *idx, node_ptr node_ref, 
			  offset_t **l,int *length) 
{
  struct idx_node *node;
  offset_t *list=*l;

  node=absolute_node(idx,node_ref);
  /* Here we add the offsets in this node to the main list */
  if(node->offsets) {
    //printf("Adding offsets from %c %u \n",node->c,node_ref);
    add_offsets_to_array(idx,node->offsets,&list,length);
  };

  /* We now recursively search for matches in our children and peers
     and add those to the list */
  if(node->child) { 
    _find_offsets(idx,node->child,&list,length);
  };

  if(node->peer) {
    _find_offsets(idx,node->peer,&list,length);
  };

  *l=list;
};

inline void  find_offsets(struct index_file *idx, node_ptr node_ref, 
			  offset_t **l,int *length) 
{
  struct idx_node *node;
  offset_t *list=*l;

  node=absolute_node(idx,node_ref);
  add_offsets_to_array(idx,node->offsets,&list,length);

  if(node->child) _find_offsets(idx, node->child,&list,length);
  *l=list;
};

void list_offsets(struct index_file *idx, node_ptr search_root, offset_t **l
		  ,int *length,char *string, int buflen) 
{
  struct idx_node *node;
  offset_t *list=*l;
  node_ptr node_ref;

  //Does this word start in this node?
  node_ref=find_node(idx, search_root ,string,buflen);

  //Add its offsets to the result set.
  if(node_ref) {
    find_offsets(idx, node_ref,&list,length);
  };

  node=absolute_node(idx, search_root);

  //This will match all words longer than this word with this word in the start
  if(node->child) {
    list_offsets(idx, node->child,&list,length,string,buflen);
  };

  //This is responsible for matching longer words of this word in the middle.
  if(node->peer) {
    list_offsets(idx, node->peer,&list,length,string,buflen);
  };

  *l=list;
};

/* Loads our heap from the file by mmaping the file into memory */
struct index_file *idx_load_from_file(unsigned char *filename) {
  struct index_file *idx;
  int page_size=getpagesize();

  idx=(struct index_file *)calloc(1,sizeof(struct index_file));
  idx->filename=strdup(filename);

  // Try to open an existing index
  idx->heap_fd=open(filename,O_RDWR);
  if(idx->heap_fd<0) 
    RAISE(E_IOERROR,NULL,"Cant open file %s",filename);
  idx->heap_file_offset=0;

  //How big is this file?
  idx->heap_size=lseek(idx->heap_fd,0,SEEK_END);

  //This is a little wastefull since we lose the remainder of the malloced chunk...
  idx->end_of_heap_ptr = idx->heap_size;
  
  //Is heap_mapped_length a multiple of page_size? if not we round it...
  if(((int)(heap_mapped_length/page_size))*page_size != heap_mapped_length) {
    heap_mapped_length=((int)(heap_mapped_length/page_size))*page_size;
  };

  //We assume that the entire file needs to be mmapped.
  idx->heap = (char *)mmap(0, idx->heap_size,
          PROT_READ | PROT_WRITE , MAP_SHARED , idx->heap_fd
          , idx->heap_file_offset);

  if(idx->heap==MAP_FAILED) 
    RAISE(E_NOMEMORY,NULL,"Unable to mmap file: %s",strerror(errno));

  idx->root=strlen(index_magic);

  // FIXME:  Implement a sliding mmap window so we can use very large files.

  return (idx);
};

/* Adds a new offset to the node node_ref.

Note that offset lists are null terminated (i.e. offset of 0
represents end of list. So we store offset+1 in the actual array.
 */
void idx_add_offset_to_list(struct index_file *idx, node_ptr node_ref,
			    unsigned long long int offset) 
{
  struct offset_list *last;
  struct  idx_node *node;
  offlist_ptr off=new_offset_list(idx);

  //  printf("Added offset %llu to index\n",offset);

  if(offset>0xffffffff00000000)
    printf("Offset less than zero at %llu\n",offset);
  
  node=absolute_node(idx,node_ref);
  last=absolute_offlist(idx, node->last_offset);

  last->next=off;
  node->last_offset=off;
  last=absolute_offlist(idx,last->next);
  last->offset=offset+1;

};

/* This indexes the buffer: 

     data,length represent a binary text buffer to index.


     base: is the base offset of this buffer within the file. (This
     offset will simply be stored in the offsets list, it may have
     arbitrary meaning depending on the application).
 */
void idx_index_buffer(struct index_file *idx, long long int base,
		      char *data,int length)
{
  char *c=data,*tmpc;

  //Temporary buffer for printing messages:
  char *tmp=(char *)malloc(BUFFER);
  struct idx_node *node;
  node_ptr node_ref;

  while(c<=data+length) {
    //Point at the current char in the buffer
    tmpc=c;
    node=absolute_node(idx, idx->root);

    //Search for the current word in the index
    node_ref= is_in_index(idx ,&c);

    //We do not allow the root node to be indexed - This stops up from matching arbitrary nulls
    if(node_ref && node_ref != idx->root) {
      node=absolute_node(idx, node_ref);
      //c has been advanced by is_in_index to the end of the word we
      //are indexing.
      //      strncpy(tmp,tmpc,max(c-tmpc,BUFFER));
      // *(tmp+(c-tmpc))=0;

      idx_add_offset_to_list(idx, node_ref,base+(tmpc-data));
    } else {
      c++;
    };
  };

  free(tmp);
};

#define INDEX_FILE "/var/tmp/test.idx"
//#define FILE_TO_INDEX "36.txt"
#define FILE_TO_INDEX "/var/tmp/test_image.dd"
//#define FILE_TO_INDEX "zero.txt"
#define KEY_WORDS "/usr/share/dict/words"

int main() {
  char *tmp=(char *)malloc(FILEBUFFER);
  char *tmp2;
  offset_t *list=NULL;
  int length=0;
  int fd;
  int count=0;
  struct index_file *idx;

  // This is an example of how to use the indexing tools, we are
  // indexing a large hdd image and then searching for all occurances
  // of the word "linux"

  if(1) {
    FILE *in=fopen(KEY_WORDS,"r");

    idx=new_index(INDEX_FILE);

    while(fgets(tmp,FILEBUFFER,in)) {
      int length=strlen(tmp)-1;
      
      if(tmp[length]=='\n') {
	tmp[length]=0;
      };
      if(strlen(tmp)>=3)
	add_word(idx,tmp,strlen(tmp));
    };
    
    //    fd=open("/var/tmp/honeypot.hda5.dd",O_RDONLY);
    fd=open(FILE_TO_INDEX,O_RDONLY);
    while((length=read(fd,tmp,FILEBUFFER))>0) {
      fprintf(stderr,"Read %u bytes\n",length);
      idx_index_buffer(idx,count,tmp,length);
      count+=length;
    };
    
    free_index(idx);
  };

  idx=idx_load_from_file(INDEX_FILE);

  fd=open(FILE_TO_INDEX,O_RDONLY);

  tmp2="document";

  printf("About to search for %s \n",tmp2);

  list_offsets(idx,idx->root,&list,&length,tmp2,strlen(tmp2));

  while(length>0) {
    lseek(fd,list[length-1],SEEK_SET);
    read(fd,tmp,100);
    tmp[30]=0;
    printf("word found at offset %llu\n\t %s\n",list[length-1],tmp);
    length--;
  };
  
  close(fd);
  free(list);

  exit(0);
};
