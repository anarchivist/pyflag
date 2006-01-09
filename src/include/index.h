#ifndef __INDEX_H
#define __INDEX_H

#include <unistd.h>

#define TYPE char

/* This object encapsulates all we need in one easy package */
struct indexing_trie {
  struct node *root;
  struct offset_list *list;
  struct pool *pool;

};


struct pool {
  char *pool;
  int size;
  //The offset to the next available byte
  int last;
};

/*
  This must be specified in pages. We specify a huge amount of memory
  here because we really do not want to be in a situation were we can
  not mremap it to the same address. Specifying a huge range is not a
  problem in linux due to the default overcommit behaviour. That is,
  the mapping is made right away, even if there is no memory available
  - memory is consumed as it is being used by the map. This is quite
  linux specific, and creates no overheads at all.
*/
#define INITIAL_POOL_SIZE getpagesize()*100000

/* For now we use the lowest HASH_DEPTH bits in the value as a hash
   function - its fast and reasonably even.
 */

//Number of bits in the hash function:
#define HASH_DEPTH 4

//The relevant bitmask
#define HASH_MASK (HASH_SIZE-1)

//The total size of hash slots = 2^HASH_DEPTH
#define HASH_SIZE (1<<HASH_DEPTH)

struct node {
  TYPE data;
  //This is the word id - not null if a word ends in this node:
  int id;
  //Links to other children in this level - note that since we have
  //multiple slots, this list may not contain all peers.
  struct node *peer;
  struct node *slots[HASH_SIZE];
};


struct offset_list {
  int size;
  int last;
  struct offset {
    int offset;
    int id;
  } *offsets;
};

//Number of items we start off with
#define INITIAL_OFFSET_LIST_SIZE 256


void idx_add_word(struct indexing_trie *trie,char *word,int len,int id);
int idx_find_longest_match(struct indexing_trie *trie,char *buffer, int len);
void idx_index_buffer(struct indexing_trie *trie,char *buffer, int len);
struct indexing_trie *idx_new_indexing_trie();
void idx_free_indexing_trie(struct indexing_trie *trie);

#endif
