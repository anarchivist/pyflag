#include "trie.h"
#include "misc.h"

TrieNode TrieNode_Con(TrieNode self) {

  INIT_LIST_HEAD(&(self->peers));

  return self;
};

/** This adds the chain representing word into self as a parent */
void TrieNode_AddWord(TrieNode self, char *word, int len, int data, 
		      enum word_types type) {
  TrieNode n;
  TrieNode i;

  /** This is the final node in the chain. We need to add a DataNode */
  if(len==0) {
    n=(TrieNode)CONSTRUCT(DataNode, DataNode, Con, self, data);
    
    list_add(&(n->peers), &(self->peers));
    return;
  };

  /** Make a new node for this letter */
  n=(TrieNode)CONSTRUCT(LiteralNode, LiteralNode, Con, self, *word);

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
  
  /** Now ask n to add the rest of the word */
  CALL(n->child, AddWord, word+1, len-1, data, type);

  return;
};

int TrieNode_Match(TrieNode self, char *buffer, int len, int *result) {
  TrieNode i;
  int found=False;
    
  /** The indexed buffer has run out */
  if(len<=0) return False;

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
     VMETHOD(Con) = TrieNode_Con;
     VMETHOD(AddWord) = TrieNode_AddWord;
     VMETHOD(Match) = TrieNode_Match;
END_VIRTUAL

LiteralNode LiteralNode_Con(LiteralNode self, char value) {
  self->value = value;
  
  INIT_LIST_HEAD(&(self->super.peers));

  talloc_set_name(self, "%s: %c", NAMEOF(self),value);

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

int LiteralNode_Match(TrieNode self, char *buffer, int len, int *result) {
  LiteralNode this=(LiteralNode) self;

  /** Here we try to check if *buffer matches us. If it does, we can
      search further otherwise we return False immediately
  */
  if(*buffer == this->value) {
    return this->__super__->Match(self->child, buffer+1, len-1, result);
  } else {
    return False;
  };
};

VIRTUAL(LiteralNode, TrieNode)
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
int DataNode_Match(TrieNode self, char *buffer, int len, unsigned int *result) {
  DataNode this = (DataNode) self;

  *result = this->data;
  
  return True;
};

VIRTUAL(DataNode, TrieNode)
     VMETHOD(Con) = DataNode_Con;
     VMETHOD(super.Match) = DataNode_Match;
END_VIRTUAL
