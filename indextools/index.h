typedef unsigned int heap_ptr;
typedef heap_ptr node_ptr;
typedef heap_ptr offlist_ptr;

struct index_file {
  char *filename;
  int heap_fd;
  node_ptr root;
  heap_ptr end_of_heap_ptr;
  long int heap_file_offset;
  long int heap_size;
  long int tree_size;
  void *heap;
};

/* 
Index tools are designed to index a dictionary of search terms in a
very large input file.

Algorithm:
-------------

Terminology: The text to be searched is referenced as 'text' The list
of words to locate within the text is called the 'dictionary'

This algorithm indexes the text at approximately constant time with
respect to the number of words in the dictionary. (i.e. we can have an
(almost) arbitrarily large dictionary to index it in constant time).

The basic method for indexing occurances of words is by assigning 
each word a unique list of offsets into the text:
*/

typedef unsigned long long int offset_t;
typedef unsigned long long int bitmap_ptr;

struct offset_list {
  offset_t offset;
  offlist_ptr next;
} __attribute__((packed));

/*
Before indexing, we construct a tree in memory representing the
dictionary. Each node in this tree is a letter of a word in the
dictionary, and each node has an arbitrary number of child nodes
representing the letters following them.

This is the node structure. Each letter in the word is represented by
a node. The letter at the end of the word has an offsets list
associated with it. (Therefore if offsets is Null, this node does not
represent a complete word).

Note that the node keeps a pointer to the end of the offsets list to
speed up appending to the list.

bitmap keeps information about which characters are in the children
list. This is done for optimisation, so we dont need to follow the
whole list to know if a character is in there or not. More about the
bitmap implementation can be found in the .c file.

*/
struct idx_node {
  unsigned char c;
  unsigned char count;
  offlist_ptr offsets;
  offlist_ptr last_offset;
  bitmap_ptr bitmap;
  node_ptr child;
  node_ptr peer;
}  __attribute__((packed));

/* 
Since the index may in fact be extremely large, it is impossible to
store it in memory. We therefore manage the data structures on disk in
our own virtual "heap". Currently we mmap a file to emulate a heap,
but in future our heap may be split across many files on possibly many
servers. The end result is that we create a class of types which
represent the data in our own virtual heap (node_ptr,offlist_ptr etc):

typedef unsigned int heap_ptr;
typedef heap_ptr node_ptr;
typedef heap_ptr offlist_ptr;

*/

/* Before actually using those structure it is necessary to convert
   those into real memory structures. Modifying the corresponding
   memory automatically changes the data on disk due to the mmap. 
*/
inline struct idx_node *absolute_node(struct index_file *idx_global,node_ptr relative);
inline struct offset_list *absolute_offlist(struct index_file *idx_global,offlist_ptr relative);

/* 
If this node represents the end of the word, offset will be non-null
and refer to a valid offset list.

If there is a char following this char in a word, child will point to
the relevant child node.

Peer will point to this node's peer (i.e. the nodes which share the
same parent as this node). The peer pointer represents a linked list
which visits all peers at this tree level.

Example:
suppost the dictionary holds the words ab,ac, acd

The first node corresponds to the letter a, and has a child node b. b
in turn has a peer c, but no children. Hence we can see that both b
and c are children to a. Both these nodes point at offset lists
storing their occurance in the text, but the c node also has another
child node d.

Indexing Algorithm:
-----------------------

Rather than search for the words in the text, we search for the text
in the dictionary. Since the dictionary is perfectly indexed this
should be very fast. There are 3 phases for the algorithm:

Building the dictionary:
==================

1) For each new word to add to the index, we search for the node
containing the first letter just below the tree root

2) If the node was found we follow it to search for the second letter
below this node, else we create a new node in the tree representing
this letter.

3) When the word is complete, we create an offset list and attach it
to the final node in the tree.

Indexing data:
===========
1) We are given a buffer of arbitrary data (could be binary too).

2) We search for the first character under the root of the tree. If
its found, we search for the second character in the buffer under that
node, and so on.

3) If we reach a node with an offset list as we are traversing the
tree, we remember this node. This node represents a complete word, and
may need to be indexed if we are unable to find longer words later.

4) If at any time we are unable to find a node representing the
character we are looking for, this means that the character is not in
the tree. We then go back to the last previously saved complete word
and append the offset to its offset list.

5) When we finished indexing a word, we advance the buffer pointer to
the end of the last complete word found, and repeat the process from
there.

Note that we are able to discount many matches based on a single
character comparison, for example if our dictionary contains english
printable words, we are able to discount all non printables
automatically by looking at the root node alone.

Currently efficiency is limited since all peers form a linked list, so
we need to traverse the list to search for matches within the list. A
future optimisation might include a hash table lookup for rapid
searching within the linked list.

Searching the index:
================

The overall result of the indexing algorithm is that we only ever
index the longest possible match, for example when indexing the word
`halloween`, we will add a single offset for the word halloween, but
will not index the following words: `hall`, `hallow`, `low`, `ween` etc....
This optimises the amount of space taken for the index as well as the
amount of time taken to actually do the indexing. The down side is
that it makes it a little more complex to search the index.

If we were actually interested in searching for the word `low` in the
example above, we would expect to find it within `halloween` as
well... There are two cases here:

1) The word we are searching for forms the start of another longer
word. For example if we are searching for `hall`. Clearly hall occures
within the word `halloween`, but since we only index the longest
possible match the offset will not be present within the node for
`hall`. 

The solution in this case is to return an array of all offsets within
the `hall` node, _as well as all offsets for all complete words under
that node_. This will include `halloween`, `halls`, `hallmark` etc...

2) The second case is where the word we are searching for occurs in
the middle of a larger word, for example if we were searching for
`low`, we would not be able to use case 1 to locate halloween, since
`halloween` is not located under `low` in the tree.

The solution in this case is to recursively search the index for all
words that contain the word `low` in them and append their offsets to
the result set as well. Note that in the word `halloween` case, after
we discover the `low` in `halloween`, we fall back into case (1) above
to actually find the offsets (which are found in the node for the last
n in the word `halloween`).

Performace effects on the searching are insignificant in most cases,
since the dictionary is quite small with respect to the size of the
indexed text, and we are doing most of the searching within the
dictionary tree. The benefits in having a much smaller index outweight
it IMHO.

*/

void add_word(struct index_file *idx_global,unsigned char *c,int length) ;
struct index_file *idx_load_from_file(unsigned char *filename);
void idx_index_buffer(struct index_file *idx_global, long long int base,char *data,int length);
struct index_file *new_index(char *filename) ;
void list_offsets(struct index_file *idx_global, node_ptr search_root, offset_t **l
		  ,int *length,char *str, int buflen);
void free_index(struct index_file *idx_global);
node_ptr find_node(struct index_file *idx_global, node_ptr root_ptr,const char *c,int length);


static char *index_magic="PYFLAGIDX";
