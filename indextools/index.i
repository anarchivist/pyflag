%module index
%include cstring.i
%include exception.i
%apply (char *STRING, int LENGTH) { (char *str, int length) };
%{
#include "except.h"
#include "index.h"

/* A simple switch that returns the swig exception given our exceptions in except.h */
  int map_exceptions_for_swig(enum _exception e) {
    switch(e) {
    case E_OVERFLOW:
      return(SWIG_OverflowError);
    case E_IOERROR:
      return(SWIG_IOError);
    case E_NOMEMORY:
      return(SWIG_MemoryError);
    case E_GENERIC:
    case E_ANY:
    default:
      return (SWIG_UnknownError);
    };
  };
  
  struct index_file *load_file(char *filename) {
    struct index_file *temp;
    TRY {
      return(idx_load_from_file(filename));
    } EXCEPT(E_ANY) {
      return((struct index_file *)(-__EXCEPT__));
    };
    return(0);
  };

  struct index_file *_new_index(char *filename) {
    TRY {
      return(new_index(filename));
    } EXCEPT(E_ANY) {
      return((struct index_file *)(-__EXCEPT__));
    };
    return(0);
  };

  /*
  int offset(offlist_ptr o) {
    struct offset_list *off=absolute_offlist(o);
    return(off->offset);
  };

  offlist_ptr offset_next(offlist_ptr o) {
    struct offset_list *off=absolute_offlist(o);
    return(off->next);
  };
  */
  /* These functions implement a low level interface to the offset
     list. These are private functions, please do not use them */

  struct list {
    offset_t *elements;
    int length;
  };

  struct list* _search_offsets(struct index_file *idx,char *str, int length) {
    struct list *l=(struct list *)malloc(sizeof(struct list));
    l->elements=NULL;
    l->length=0;
    list_offsets(idx,idx->root,&(l->elements),&(l->length),str,length);
    return(l);
  };
  
  long long int _read_offset(struct list *l,int index) {
    if(index<0 || index >= l->length) return(-1);
    return l->elements[index];
  };

  void _free_list(struct list *l) {
    free(l->elements);
    free(l);
  };

%}

%exception  load_file {
  $action
    if((int)result<0) {
      SWIG_exception(map_exceptions_for_swig(-(int)result),except_str);
    };
}


%exception  _new_index {
  $action
    if((int)result<0) {
      SWIG_exception(map_exceptions_for_swig(-(int)result),except_str);
    };
}


%pythoncode %{
class search:
    """ A wrapper class to encapsulate the result set of searching the index. 

    This class creates an iterator returning all the offsets where string is found within index.
    """
    def __init__(self,idx,string):
        """ Constructor for result set

       @arg index: a reference to an index which was previously loaded or created
       @arg string: The string to search for in the index 
        """
        self.list=_search_offsets(idx,string)
        self.i=0

    def __iter__(self):
        return self

    def next(self):
        result =  _read_offset(self.list,self.i)
        self.i+=1
        if result<0:
             raise StopIteration
        return result

    def __del__(self):
        _free_list(self.list)

class index:
  """ Index object. 

  This object controls access to the underlying indexing engine. Please do not use the underlying engine directly, since this object performs memory management by freeing the index in its destructor.
  """
  def __init__(self,filename):
       """ Creates a new instance of an index. 

       If load is None, we create a new index, else we try to open an existing index for searching.
       """
       self.idx=_new_index(filename)
       
  def index_buffer(self,base,str):
       """ Indexes the string.

       @arg base: A number representing the offset of the current str within the larger data set
       @arg str:    A buffer of data to index.
       """
       idx_index_buffer(self.idx,base,str)

  def add(self,word):
      """ Adds a word to the index. """
      add_word(self.idx,word)

  def search(self,word):
      """ Searches the index for a word.
   
      @arg word: Word to search for.
      @return: A search object iterator.
      """
      return search(self.idx,word)

  def __del__(self):
      try:
            free_index(self.idx)
      except AttributeError:
            pass

class Load(index):
    def __init__(self,filename):
         self.idx=load_file(filename)         
 %}

struct list* _search_offsets(struct index_file *idx,char *str, int length);
long long int _read_offset(struct list *l,int index);
void _free_list(struct list *l);
void add_word(struct index_file *idx,char *str,int length) ;
void idx_index_buffer(struct index_file *idx, long long int base,char *str,int length);
struct index_file *_new_index(char *filename) ;
void list_offsets(struct index_file *idx, node_ptr search_root, offset_t **l
		  ,int *length,char *str, int buflen);
void free_index(struct index_file *idx);
struct index_file *load_file(char *filename);
