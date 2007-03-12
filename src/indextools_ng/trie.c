#include "trie.h"
#include "misc.h"

/** This function reads and interprets the ranges:

* Means zero or more occurances,
+ Means one or more occurances,
{lower,upper} sets a range.

The values are set in the lower,upper if they were found. buffer and
len are suitably adjusted.
*/
void check_for_repeat(unsigned char *lower, unsigned char *upper, 
			 char **buffer, int *len) {
  switch(**buffer) {
  case '?':
    *lower=0;
    *upper=1;
    goto repeat_return;

  case '*':
    *lower=0;
    goto repeat_return;
  case '+':
    *lower=1;
    goto repeat_return;
  case '{':
    {
      int l,u;

      if(sscanf(*buffer, "{%u,%u}", &l, &u) < 2) {
	printf("Unable to understand range specification %s\n", *buffer);
	return;
      } else {
	while(*(*buffer-1)!='}') {
	  (*buffer)++;
	  (*len)--;
	};
	
	*lower=(unsigned char)l;
	*upper=(unsigned char)u;
	return;
      };
    };
  default:
    /** Do nothing if there are no ranges */
    return;
  };

 repeat_return:
  *upper=MAX_MATCH_LENGTH;
  (*buffer)++; (*len)--;
  return;
};

/** This function builds a character map from a character class
    specification. (e.g. [^1-9abc]). buffer,len are the buffer to read
    the specification from, we advance those past the
    specification. We return a map (i.e. char x[256] where x[char] =
    True for char in character class.
*/
char *build_character_class(char **buffer, int *len) {
  int inverted = False;
  char *map;

  // We expect to be called on a [
  if(**buffer == '[') {
    (*buffer)++; (*len)--;
  } else return NULL;

  map = talloc_size(NULL, 258);
  memset(map, 0, 256);
  
  if(**buffer == '^') {
    inverted = True;
    (*buffer)++; (*len)--;
  };

  while(**buffer != ']' && *len>1) {
    //Range specified:
    if(**buffer=='-') {
      int i;

      for(i= *(*buffer-1); i<= *(*buffer+1); i++) {
	map[i] = True;
      };

    } else if(**buffer=='\\') {
      // We try to parse out the \\ character class.
      CharacterClassNode n = CONSTRUCT(CharacterClassNode, CharacterClassNode, 
					 Con, NULL, buffer, len);

      // This can produce either a LiteralNode or a true CharacterClassNode:
      if(!n) {
	continue;
      };

      if(ISINSTANCE(n, LiteralNode)) {
	LiteralNode this=(LiteralNode)n;

	// Set the literal node's value in the map
	map[(unsigned int)(unsigned char)(this->value)] = True;
      } else if(ISINSTANCE(n, CharacterClassNode)) {
	int i;

	// Merge the character maps together
	for(i=0;i<256; i++) {
	  map[i] |= n->map[i];
	};
      };

      talloc_free(n);
      // We do not need to advance buffer because
      // CharacterClassNode_Con has done so.
      continue; 
    } else {
      map[(int)*(unsigned char *)*buffer] = True;
    };
    
    (*buffer)++, (*len)--;
  };

  if(inverted) {
    int i;

    for(i=0;i<256; i++) map[i] = !map[i];
  };

  (*buffer)++; (*len)--; 
  return map;
};

/** 
    Adds a node to a peer list only if it doesnt already exist in
   there.  Frees the node if its already there.
*/
static TrieNode add_unique_to_peer_list(struct list_head *l, TrieNode n, 
					int (*cb)(TrieNode a,TrieNode b)) {
    int found=False;
    TrieNode i;

    list_for_each_entry(i, l, peers) {
      if(cb(i,n)) {
	found = True;
	break;
      };
    };

    if(!found) {
      list_add(&(n->peers), l);
    } else {
      talloc_free(n);
      n=i;
    }

    return n;
};

// This is a character comparison map it represents those characters
// which must have an offset added to their value in order to
// normalise them. This is not unicode aware but is very fast.
char cmap[256] = { ['A' ... 'Z']='a'-'A' };

int Compare_literal_nodes(TrieNode a, TrieNode b) {
  if(!ISSUBCLASS(a,LiteralNode) || !ISSUBCLASS(b,LiteralNode)) 
    return False;

  char left=((LiteralNode)a)->value;
  char right= ((LiteralNode)b)->value;

  // If the two nodes have a different comparison function - they are
  // not the same
  return (left==right && a->compare == b->compare);
};

TrieNode TrieNode_Con(TrieNode self) {
  INIT_LIST_HEAD(&(self->peers));

  return self;
};

int TrieNode_compare(TrieNode self, char **buffer, int *len) {
  return True;
};

/** Works out which node comes next by looking at the special
    characters in word. This function is responsible for parsing
    character classes, multiples etc.

    We return NULL to indicate that no nodes are available (e.g. end
    of word etc).
 */
static TrieNode MakeNextNode(TrieNode self, char **word, int *len, 
			     long int data, enum word_types type) {
  TrieNode n=NULL;

  /** Look for \ escapes */
  if(**word == '\\') {
    /** CharacterClassNode accounds for things like \d \w etc */
    n=(TrieNode)CONSTRUCT(CharacterClassNode, CharacterClassNode, 
			  Con, self, word, len);

    /** Look for explicit character classes [0-2] etc */
  } else if (**word == '[') {
    char *map = build_character_class(word, len);
    
    if(map) {
      n=(TrieNode)CONSTRUCT(CharacterClassNode, CharacterClassNode,
			    Con_with_map, self, word,len, map);
      
      /** Steal this map: */
      if(n)
	talloc_steal(n, map);
    };

    /** Look for a wildcard specifier (matches everything) */
  } else if(**word == '.') {
    n=(TrieNode)CONSTRUCT(CharacterClassNode, CharacterClassNode,
			  Con_with_map, self, word,len, NULL);
    
    if(n)
      n->compare = CharacterClass_wildcard_compare;

    (*word)++; (*len)--;
  };

  /** Otherwise we just add a literal node */
  if(!n) {
    /** Node is literal */
    n=(TrieNode)CONSTRUCT(LiteralNode, LiteralNode, Con, self, word, len);    
  };

  /** Now check for ranges e.g. {1,4} */
  if(*len > 0) {
    check_for_repeat(&(n->lower_limit), &(n->upper_limit), word, len);
  };

  return n;
};

/** This adds the chain representing word into self as a parent */
void TrieNode_AddWord(TrieNode self, char **word, int *len, long int data, 
		      enum word_types type) {
  int i;
  TrieNode n;
  int (*comparison_function)(TrieNode a, TrieNode b) = Compare_literal_nodes;
  
  /** This is the final node in the chain. We need to add a DataNode */
  if(*len==0) {
    n=(TrieNode)CONSTRUCT(DataNode, DataNode, Con, self, data);
  } else if(type==WORD_ENGLISH) {
       n = (TrieNode)CONSTRUCT(LiteralNode, LiteralNode, Con, self, word, len); 
       if(!n) return;

       n->compare = LiteralNode_casecompare;
  } else if(type==WORD_EXTENDED) {
    n=MakeNextNode(self, word, len, data, type); 
  } else {
    n = (TrieNode)CONSTRUCT(LiteralNode, LiteralNode, Con, self, word, len);   
  };

  // We failed to add a node?
  if(!n) return;

  /** If the node is a literal node, we can store it in our hash
      table: 
  */
  if(ISINSTANCE(n, LiteralNode)) {
    LiteralNode this = (LiteralNode)n;

    // Calculate the hash value of the literal node
    i = 0x0F & this->value;

    // Make sure there is a list head ready
    if(!self->hash_table[i]) {
      self->hash_table[i] = CONSTRUCT(TrieNode, TrieNode, Con, self);
    };
    
    n=add_unique_to_peer_list(&(self->hash_table[i]->peers), n, 
			      comparison_function);
  } else {
    /** Otherwise Add the node to our children list */
    if(!self->child) 
      self->child = CONSTRUCT(TrieNode, TrieNode, Con, self);

    n=add_unique_to_peer_list(&(self->child->peers),n,
			      comparison_function);
  }

  /** Now ask n to add the rest of the word */  
  CALL(n, AddWord, word, len, data, type);

  return;
};

int TrieNode_Match(TrieNode self, char *start, char **buffer, int *len, PyObject *result) {
  int i;
  int found=False;
  uint16_t h;
  TrieNode j;

  /** First check for the lower limit of char counts */
  for(i=0;i<self->lower_limit;i++) {
    if(!self->compare(self,buffer,len))
      return False;
  };

  /** Now check for the range - this makes us greedy since it will
      consume as many chars as possible between the lower_limit and
      the upper_limit
  */
  for(i=self->lower_limit; i<self->upper_limit; i++) {
    if(!self->compare(self,buffer, len))
      break;
  };

  /** Check to see if there is a literal node matching in our hash
      table 
  */
  h=0x0F & **buffer;
  if(self->hash_table[h]) {
    list_for_each_entry(j, &(self->hash_table[h]->peers), peers) {
      char *buf = *buffer;
      int length = *len;
      
      if(j->Match(j, start, &buf, &length, result))
	found = True;
    };
  };
  
  /** Now search our children for a match: */
  if(self->child) {
    list_for_each_entry(j, &(self->child->peers), peers) {
      char *buf = *buffer;
	int length = *len;
	
	if(j->Match(j, start, &buf, &length, result))
	  found = True;
    };
  };
  
  return found;
};

VIRTUAL(TrieNode, Object)
     VATTR(lower_limit)=1;
     VATTR(upper_limit)=1;

     VMETHOD(Con) = TrieNode_Con;
     VMETHOD(AddWord) = TrieNode_AddWord;
     VMETHOD(Match) = TrieNode_Match;
     VMETHOD(compare) = TrieNode_compare;
END_VIRTUAL

LiteralNode LiteralNode_Con(LiteralNode self, char **value, int *len) {
  // Lowercase the value.
  //  self->value = **value+cmap[**value];
  self->value = **value;

#ifdef __DEBUG_V_
  talloc_set_name(self, "%s: %c", NAMEOF(self),**value);
#endif

  (*value)++;
  (*len)--;

  INIT_LIST_HEAD(&(self->super.peers));

  return self;
};

// A variation of the compare method with case insensitive comparisons
int LiteralNode_casecompare(TrieNode self, char **buffer, int *len) {
  LiteralNode this = (LiteralNode)self;
  int result = **buffer+cmap[(unsigned int)**(unsigned char **)buffer]==this->value;

  if(result)
    (*buffer)++; (*len)--;

  return result;
};

int LiteralNode_compare(TrieNode self, char **buffer, int *len) {
  LiteralNode this = (LiteralNode)self;
  int result = **buffer==this->value;

  if(result)
    (*buffer)++; (*len)--;

  return result;
};

VIRTUAL(LiteralNode, TrieNode)
     VATTR(super.lower_limit)=1;
     VATTR(super.upper_limit)=1;

     VMETHOD(Con) = LiteralNode_Con;
     VMETHOD(super.compare) = LiteralNode_compare;
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

#ifdef __DEBUG_V_
  talloc_set_name(self, "DataNode: %u", data);
#endif

  return self;
};

/** Data nodes automatically match - if we get to them, we have a
    match. We also can set the result 
*/
int DataNode_Match(TrieNode self, char *start, char **buffer, int *len, PyObject *result) {
  DataNode this = (DataNode) self;
  
  /** Append the hit to the list */
  PyList_Append(result, Py_BuildValue("ii",this->data, *buffer-start));
  
  return True;
};

void DataNode_AddWord(TrieNode self, char **word, int *len, long int data, 
		      enum word_types type) {
  return;
};

VIRTUAL(DataNode, TrieNode)
     VMETHOD(Con) = DataNode_Con;
     VMETHOD(super.Match) = DataNode_Match;
     VMETHOD(super.AddWord) = DataNode_AddWord;
END_VIRTUAL

/** These are some standard character maps - they may need to be
    edited for UTF8?? */
static char char_map_digits[256] = { ['0' ... '9'] = 1 };
static char char_map_word[256]   = { ['a' ... 'z'] = 1, ['A' ... 'Z'] = 1};
static char char_space_word[256] = { ['\n']=1, ['\r']=1, [' ']=1, ['\t']=1 };

CharacterClassNode CharacterClassNode_Con_with_map(CharacterClassNode self,
						   char **word, int *len, 
						   char *map) {
  CharacterClassNode this = (CharacterClassNode) self;

  this->map = map;

  return self;
};


CharacterClassNode CharacterClassNode_Con(CharacterClassNode self,
					  char **word, int *len) {
  CharacterClassNode this = (CharacterClassNode) self;

#ifdef __DEBUG_V_
  talloc_set_name(self, "%s: %c", NAMEOF(self),**word);
#endif

  // We expect to be called on a \\ character:
  if(**word != '\\') {
    printf("Error CharacterClassNode not constructed on \\\n");
    talloc_free(self);
    return NULL;
  };
  
  (*word)++; (*len)--;

  switch(**word) {
  case 'd':
    this->map = char_map_digits;
    break;

  case 'w':
    this->map = char_map_word;
    break;

  case 's':
    this->map = char_space_word;
    break;

    // This is a hex value literal (e.g. \xff):
  case 'x':
    {
      // Make a dummy LiteralNode and set its value
      LiteralNode result = CONSTRUCT(LiteralNode, LiteralNode, Con,
				     self, word, len);

      unsigned int x;
      if(sscanf(*word, "%02x", &x) < 1) {
	char tmp[10];
	strncpy(tmp, *word, 9);
	tmp[10]=0;

	printf("Unable to understand hex character %s\n", tmp);
	return NULL;
      } else {
	(*word)+=2;
	(*len)-=2;
      };

      result->value = x;
      return (CharacterClassNode)result;
    };
    break;

  default:
    // Unknown character class- just use a literal:
    return (CharacterClassNode)CONSTRUCT(LiteralNode, LiteralNode, Con,
					 self, word, len);
  }
  
  (*len)--;
  (*word)++;

  return self;
};

int CharacterClassNode_compare(TrieNode self, char **buffer, int *len) {
  CharacterClassNode this=(CharacterClassNode) self;
  int index = *(unsigned char *)*buffer;

  if(this->map[index]) {
    (*buffer)++; (*len)--;
    return True;
  };

  return False;
};

/** This is used to make a wildcard comparison - always matches anything */
int CharacterClass_wildcard_compare(TrieNode self, char **buffer, int *len) {
  (*buffer)++; (*len)--;
  return 1;
};

VIRTUAL(CharacterClassNode, TrieNode)
     VMETHOD(Con) = CharacterClassNode_Con; 
     VMETHOD(Con_with_map) = CharacterClassNode_Con_with_map;
     VMETHOD(super.compare) = CharacterClassNode_compare;
END_VIRTUAL
