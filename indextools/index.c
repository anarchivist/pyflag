/* This is an implementation of a trie/hashtable design for rapid
   searching and classifying of text. The meaning of "text" is very
   loose here, including arbitrary binary strings.

   The intention is that the following rough usage pattern take place:
   1. create a memory pool object for the trie
   2. Add words to it.
   3. Index a buffer against the added words. This will allocate an internal list of offset pointers.
   4. Grab the list for storage in the db.
   5. Goto 3 until end of data.
 */

/* The pool: We allocate memory in a pool for building the
   trie. Memory allocation for the trie is special because we always
   need to add nodes, but never delete nodes individually. We need to
   deallocate the pool at once when finished. Using a pool to manage
   memory saves at least 6-10 bytes per node due to not needing
   glibc's malloc structures.
 */
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include "except.h"
#include "index.h"
#include <errno.h>
#include <ctype.h>

extern int errno;

#define NEW(x) (x *)calloc(sizeof(x),1)

/* We use mmap to obtain our memory for the pool because we need to
   ensure that the memory can be grown without moving it (that is why
   realloc is unsuitable). Moving the memory address will invalidate
   all pointers within it.
 */
static struct pool *idx_new_pool(void)
{
  struct pool *p = NEW(struct pool);

  //  p->pool = (char *)malloc(INITIAL_POOL_SIZE);
  p->pool = (char *)mmap(0,INITIAL_POOL_SIZE, PROT_READ|PROT_WRITE,
			 MAP_PRIVATE|MAP_ANONYMOUS,0,0);
  p->size = INITIAL_POOL_SIZE;

  if(!p->pool) RAISE(E_NOMEMORY,NULL,"Unable to allocate memory for pool");
  return p;
};

// Release the pool
static void idx_pool_release(struct pool *pool) {
  munmap(pool->pool,pool->size);
  free(pool);
};

/* Allocates size bytes off the pool, growing it if needed.

We demand that memory not be relocated because this will invalidate
all pointers within the pool. If the initial map is too small the
chances of not being able to remap are fairly high. We therefore
choose to map a huge anonymous region relying on linux's overcommit
behaviour to ensure the system is not affected.
 */
static void *idx_pool_allocate(struct pool *pool,int size)
{
  char *result;
  int old_size=pool->size;

  while(pool->last+size>pool->size) {
    //Grow the pool
    pool->size+=INITIAL_POOL_SIZE;
    //    pool->pool = (char *)realloc(pool->pool,pool->size);
    pool->pool = (char *)mremap(pool->pool,old_size,pool->size,0);
    if(pool->pool==MAP_FAILED) RAISE(E_NOMEMORY,NULL,"Error in mremap: %s",strerror(errno));
  };
  
  result = pool->pool+pool->last;
  pool->last+=size;

  return result;
};

/* Create and initialise a new node */
static struct node *idx_new_node(struct pool *pool,TYPE data) 
{
  struct node *node;

  node=(struct node *)idx_pool_allocate(pool,sizeof(struct node));

  node->data=data;

  return node;
};

/* Comparison function for equating characters in the trie */
static inline int compare(TYPE a,TYPE b) {
  return(a==b);
};

/* Given an int data, we calculate a slot position */
static inline int hash_function(TYPE data)
{
  return(HASH_MASK & data);
};

/* Allocates a new node and add it to the parent */
static struct node *idx_add_data_to_node(struct pool *pool,struct node *parent,TYPE data)
{
  struct node *tmp,*child=idx_new_node(pool,data);
  int slot;

  //Find out which slot this belongs in:
  slot = hash_function(data);

  if(parent->slots[slot]) {
    //Find the end of the list:
    for(tmp=parent->slots[slot];tmp->peer;tmp=tmp->peer);
    
    tmp->peer=child;
  } else {
    //Install this child as the first item.
    parent->slots[slot]=child;
  }

  return child;
};

/* Retrieves the child from the parent node with this data */
struct node *idx_get_child(struct node *parent,TYPE data)
{
  struct node *tmp=parent;
  int slot=hash_function(data);
  
  for(tmp=parent->slots[slot];tmp;tmp=tmp->peer) {
    if(compare(tmp->data,data)) return(tmp);
  };
  
  return NULL;
};

/* Adds the word in word,len to the trie at root 

parent - The node to start adding it from
word - the string to add
len - the length of this string
id - the ID to mark this string as

Note that this is a private function
*/
static void add_word(struct pool *pool,struct node *parent,char *word,int len,int id)
{
  struct node *child;

  //We mark the end of the word
  if(len==0) {
    parent->id=id;
    return;
  };

  //Do we already have this child in the trie?
  child=idx_get_child(parent,*word);
  if(!child) {
    child=idx_add_data_to_node(pool,parent,*word);
  };

  add_word(pool,child,word+1,len-1,id);
};

/* A public wrapper for adding words */
void idx_add_word(struct indexing_trie *trie,char *word,int len,int id)
{
  add_word(trie->pool,trie->root,word,len,id);
};

/* Find the longest match in the buffer given the trie in root */
int idx_find_longest_match(struct indexing_trie *trie,char *buffer, int len)
{
  struct node *root=trie->root;
  struct node *tmp=0,*child=0;
  int best_id=0;
  int i=0;

  tmp=root;
  while(1) {
    child = idx_get_child(tmp,buffer[i]);

    //That is the longest match and we are at the bottom of the trie:
    //we return the best id
    if(!child) {
      return(best_id);
    };

    //If this node is the end of a word we update our longest match
    if(child->id) best_id=child->id;
    tmp=child;
    i++;

    //Are we at the end of the buffer?
    if(i>len) return(0);
  };
};

static struct offset_list *idx_new_offset_list() {
  struct offset_list *result=NEW(struct offset_list);

  result->size=INITIAL_OFFSET_LIST_SIZE;
  result->offsets = (struct offset *)malloc(sizeof(struct offset)*result->size);
  return result;
};

/* Adds to the offset list, possibly growing it */
void idx_add_to_offset_list(struct offset_list *list,int offset, int id)
{
  struct offset *off;
  
  off=list->offsets;

  off[list->last].offset=offset;
  off[list->last].id=id;
  list->last++;
  if(list->last>=list->size) {
    list->size+=INITIAL_OFFSET_LIST_SIZE;
    list->offsets=(struct offset *)realloc(list->offsets,list->size);
  };
};

/* 
   Index the buffer in buffer and fill offsets in the list.

   Note that we invalidate the list here, and reallocate it.
 */
void idx_index_buffer(struct indexing_trie *trie,char *buffer, int len) 
{
  struct offset_list *list=trie->list;
  int i=0;
  int id;

  //Initialise the list again - this returns memory back in case we
  //had a spike:
  free(list->offsets);
  list->size=INITIAL_OFFSET_LIST_SIZE;
  list->last=0;
  list->offsets = (struct offset *)malloc(sizeof(struct offset)*list->size);

  while(len>0) {
    id=idx_find_longest_match(trie,buffer+i,len);
    if(id)
      idx_add_to_offset_list(list,i,id);
    i++;
    len--;
  };
};

void print_node(struct node *node,int depth)
{
  int i;
  struct node *item=node;
  char tmp[]="---------------------";

  tmp[depth]=0;
  printf("%s%c\n",tmp,node->data);
  for(i=0;i<HASH_SIZE;i++) {
    //    printf("%sslot %u:\n",tmp,i);
    for(item=node->slots[i];item;item=item->peer) {
      print_node(item,depth+1);
    };
  };
};

/* Create a new indexing trie */
struct indexing_trie *idx_new_indexing_trie()
{
  struct indexing_trie *trie=NEW(struct indexing_trie);

  trie->pool = idx_new_pool();
  trie->root = idx_new_node(trie->pool,0);
  trie->list = idx_new_offset_list();
  
  return trie;
};

void idx_free_indexing_trie(struct indexing_trie *trie) {
  //Deallocate the pool:
  idx_pool_release(trie->pool);
  free(trie->list->offsets);
  free(trie->list);
};

int main() {
  struct indexing_trie *trie = idx_new_indexing_trie();
  int i=1,fd;
  char buffer[2500];
  int len;
  int offset=0;

  struct offset *off;
  FILE *file=fopen("/usr/share/dict/words","r");
  
  do {
    fgets(buffer,250,file);
    //chomp whitespace off the end of words:
    len=strlen(buffer)-1;
    while(len>0 && isspace(buffer[len])) len--;

    buffer[len+1]=0;
    //    printf("adding %s with id %u\n",buffer,i);
    if(len>3) {
      idx_add_word(trie,buffer,len+1,i);
      i++;
    };
  }while(!feof(file));

  fclose(file);

  fd=open("/var/tmp/demo/quiet.dump",O_RDONLY );
  while(1) {
    len=read(fd,buffer,2000);
    if(!len) break;
    idx_index_buffer(trie,buffer,len);    


    //Print the results:
    for(i=0;i<trie->list->last;i++) {
      off=trie->list->offsets;
      printf("Found id %u at offset %u\n",
	     off[i].id,off[i].offset+offset);
    };

    offset+=len;
  };
  close(fd);

  printf("%s",buffer);

  return 0;
};
