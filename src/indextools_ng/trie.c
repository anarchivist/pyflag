#include "trie.h"
#include "misc.h"

/** This function reads the wildcards and ranges:

* Means zero or more occurances,
+ Means one or more occurances,
{lower,upper} sets a range.

The values are set in the lower,upper if they were found. buffer and
len are suitably adjusted.
*/
void check_for_wildcards(unsigned char *lower, unsigned char *upper, 
			 char **buffer, int *len) {
  switch(**buffer) {
  case '*':
    *lower=0;
    goto wildcards_return;
  case '+':
    *lower=1;
    goto wildcards_return;
  case '{':
    {
      int l,u;
      if(sscanf(*buffer, "{%u,%u}", &l, &u) < 2) {
	printf("Unable to understand range specification %s\n", *buffer);
	return;
      } else {
	while(**buffer!='}') {
	  *(buffer)++;
	  *(len)--;
	};

	*lower=(unsigned char)l;
	*upper=(unsigned char)u;
	return;
      };
    };
  default:
    /** Do nothing if there are not ranges */
    return;
  };

 wildcards_return:
  *upper=MAX_MATCH_LENGTH;
  *buffer = *buffer+1;
  *len = *len -1;
  return;
};


TrieNode TrieNode_Con(TrieNode self) {

  INIT_LIST_HEAD(&(self->peers));

  return self;
};

/** This adds the chain representing word into self as a parent */
void TrieNode_AddWord(TrieNode self, char **word, int *len, long int data, 
		      enum word_types type) {
  TrieNode n=NULL;
  TrieNode i;

  /** This is the final node in the chain. We need to add a DataNode */
  if(*len==0) {
    n=(TrieNode)CONSTRUCT(DataNode, DataNode, Con, self, data);
    
    list_add(&(n->peers), &(self->peers));
    return;
  };

  if(**word == '\\') {
    *word=*word+1;
    *len=*len-1;
    /** Two \\ in a row will be replaced by one \ */
    if(**word != '\\') {
      n=(TrieNode)CONSTRUCT(CharacterClassNode, CharacterClassNode, 
			    Con, self, word, len);
    };
  };

  if(!n) {
    /** Node is literal */
    n=(TrieNode)CONSTRUCT(LiteralNode, LiteralNode, Con, self, word, len);
  };

  /** Check to see if the new item is in our peers list: */
  list_for_each_entry(i, &(self->peers), peers) {
    if(n->__eq__(n, i)) {
      talloc_free(n);
      n=i;
      break;
    };
  };
  
  /** Couldnt find the node in the peers list: add to peers list */
  if(n!=i) {
    list_add(&(n->peers), &(self->peers));
  };

  if(!n->child) {
    /** Child is a list head for the children list: */
    n->child = CONSTRUCT(TrieNode, TrieNode, Con, self);
  };
  
  (*len)--;
  (*word)++;

  /** Now check for wildcards and ranges */
  check_for_wildcards(&(self->lower_limit), &(self->upper_limit), word, len);

  /** Now ask n to add the rest of the word */  
  CALL(n->child, AddWord, word, len, data, type);

  printf("%u %u\n", self->lower_limit, self->upper_limit);
  return;
};

int TrieNode_Match(TrieNode self, char **buffer, int *len, PyObject *result) {
  TrieNode i;
  int found=False;
    
  /** The indexed buffer has run out */
  if(*len<=0) return False;

  /** If one of our children is a DataNode we adjust result. This loop
      goes over all our children in case one of them is a DataNode
  */
  list_for_each_entry(i, &(self->peers), peers) {
    if(i->Match(i, buffer, len, result))
      found=True;
  };
  
  return found;
};

VIRTUAL(TrieNode, Object)
     VATTR(lower_limit)=1;
     VATTR(upper_limit)=1;

     VMETHOD(Con) = TrieNode_Con;
     VMETHOD(AddWord) = TrieNode_AddWord;
     VMETHOD(Match) = TrieNode_Match;
END_VIRTUAL

LiteralNode LiteralNode_Con(LiteralNode self, char **value, int *len) {
  self->value = **value;
  
  INIT_LIST_HEAD(&(self->super.peers));

  talloc_set_name(self, "%s: %c", NAMEOF(self),**value);

  return self;
};

int LiteralNode_eq(TrieNode self, TrieNode tested) {
  LiteralNode this=(LiteralNode)self;
  LiteralNode this_tested = (LiteralNode)tested;

  /** If we dont belong to the same class, we cant be equal */
  if(CLASSOF(tested)!=CLASSOF(self)) return 0;

  /** If our literal values are the same, we are equal */
  if(this->value == this_tested->value) return 1;

  return 0;
};

int LiteralNode_Match(TrieNode self, char **buffer, int *len, PyObject *result) {
  LiteralNode this=(LiteralNode) self;
  int i;

  /** First check for the lower limit of char counts */
  for(i=0;i<self->lower_limit;i++) {
    if(**buffer!=this->value)
      return False;
  };

  /** Now check for the range - this makes us greedy since it will
      consume as many chars as possible between the lower_limit and
      the upper_limit
  */
  for(i=self->lower_limit; i<self->upper_limit; i++) {
    if(*(*buffer + i) != this->value) {
      break;
    };
  };

  {
    //Consume all the chars and keep testing:
    char *new_buffer=*buffer+i;
    int new_length = *len-i;
    return this->__super__->Match(self->child, &new_buffer, &new_length, result);
  };
};

VIRTUAL(LiteralNode, TrieNode)
     VATTR(super.lower_limit)=1;
     VATTR(super.upper_limit)=1;

     VMETHOD(Con) = LiteralNode_Con;
     VMETHOD(super.__eq__) = LiteralNode_eq;
     VMETHOD(super.Match) = LiteralNode_Match;
END_VIRTUAL

RootNode RootNode_Con(RootNode this) {
  
  INIT_LIST_HEAD(&(this->super.peers));

  return this;
};

VIRTUAL(RootNode, TrieNode)
     VMETHOD(Con) = RootNode_Con;
END_VIRTUAL

DataNode DataNode_Con(DataNode self, int data) {
  self->data = data;
  
  INIT_LIST_HEAD(&(self->super.peers));

  talloc_set_name(self, "DataNode: %u", data);

  return self;
};

/** Data nodes automatically match - if we get to them, we have a
    match. We also can set the result 
*/
int DataNode_Match(TrieNode self, char **buffer, int *len, PyObject *result) {
  DataNode this = (DataNode) self;
  
  /** Append the hit to the list */
  PyList_Append(result,PyInt_FromLong(this->data));
  
  return True;
};

VIRTUAL(DataNode, TrieNode)
     VMETHOD(Con) = DataNode_Con;
     VMETHOD(super.Match) = DataNode_Match;
END_VIRTUAL

/** These are some standard character maps - they may need to be
    edited for UTF8?? */
static char char_map_digits[256] = { ['0' ... '9'] = 1 };
static char char_map_word[256]   = { ['a' ... 'z'] = 1, ['A' ... 'Z'] = 1};

CharacterClassNode CharacterClassNode_Con(CharacterClassNode self,
					  char **word, int *len) {
  CharacterClassNode this = (CharacterClassNode) self;

  talloc_set_name(self, "%s: %c", NAMEOF(self),**word);

  switch(**word) {
  case 'd':
    this->map = char_map_digits;
    break;
  case 'w':
    this->map = char_map_word;
    break;
  default:
    // Unknown character class- just use a literal:
    return (CharacterClassNode)CONSTRUCT(LiteralNode, LiteralNode, Con,
					 self, word, len);
  }

  return self;
};

int CharacterClassNode_Match(TrieNode self, char **buffer, int *len, PyObject *result) {
  CharacterClassNode this=(CharacterClassNode) self;
  int index = *(unsigned char *)*buffer;

  if(this->map[index]) {
    //Consume one char and keep testing:
    *buffer=*buffer+1;
    *len=*len-1;
    return this->__super__->Match(self->child, buffer, len, result);
  } else {
    return False;
  };
};

VIRTUAL(CharacterClassNode, TrieNode)
     VMETHOD(Con) = CharacterClassNode_Con;
     VMETHOD(super.Match) = CharacterClassNode_Match;
END_VIRTUAL