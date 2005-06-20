%module index
%include cstring.i
%include exception.i
%apply (char *STRING, int LENGTH) { (char *str, int length) };
%cstring_output_allocate_size(char **s, int *slen, free(*$1));
%{
#include "except.h"
#include "index.h"

  /* This function returns the offset table as raw data. This is then
     used by the python code to directly work with the raw data. This
     is a bit of a hack, but it allows passing vast numbers of offsets
     from the c layer to the python layer with only a single
     transition call.
   */

  void get_offset_table(struct indexing_trie *trie,char **s, int *slen) {
    *slen=trie->list->last * sizeof(struct offset);
    *s = (char *)malloc(*slen);
    memcpy(*s,trie->list->offsets,*slen);
//    printf("Allocating %u bytes for %u elements\n",*slen,trie->list->last);
  };

%}

%pythoncode %{
import struct

class offsets:
   """ An iterator to iterate over all the offsets """
   ## The format of the offset struct
   fmt = "@ii"

   def __init__(self,data):
       """ Data is the raw data as passed by get_offset_table """
       self.data = data
       ## This is the size of each offset struct
       self.size = struct.calcsize(self.fmt)
       self.element=0

   def __iter__(self):
       return self

   def next(self):
#       print "Getting %s element (%s)" % (self.element,len(self.data))
       try:
           s=self.data[self.element:self.element+self.size]
           
           if len(s)<self.size: raise StopIteration
           self.offset,self.id = struct.unpack(self.fmt,s)
           self.element+=self.size
           return self
       except IndexError:
           raise StopIteration

class index:
    """ This class encapsulates the indexing library into a single object """
    def __init__(self):
        self.idx=idx_new_indexing_trie()

    def add_word(self,word,id):
        idx_add_word(self.idx,word,id)

    def index_buffer(self,buffer):
        idx_index_buffer(self.idx,buffer)

    def get_offsets(self):
        return offsets(get_offset_table(self.idx))
    
    def __del__(self):
        idx_free_indexing_trie(self.idx)
%}

void idx_add_word(struct indexing_trie *trie,char *str,int length,int id);
void idx_index_buffer(struct indexing_trie *trie,char *str, int length);
struct indexing_trie *idx_new_indexing_trie();
void get_offset_table(struct indexing_trie *trie,char **s, int *slen);
void idx_free_indexing_trie(struct indexing_trie *trie);
