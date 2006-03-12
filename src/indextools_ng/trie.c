#include "trie.h"

/** This adds the chain representing word into self as a parent */
void TrieNode_AddWord(TrieNode self, char *word, int len, uint64_t data, 
		      enum word_types type) {
  TrieNode n;
  TrieNode i;

  if(len<=0) return;

  n=(TrieNode)CONSTRUCT(LiteralNode, LiteralNode, Con, self, *word);

  /** Check to see if the new item is already in our children list: */
  list_for_each_entry(i, &(self->children), children) {
    if(n->__eq__(n, i)) {
      talloc_free(n);
      n=i;
      break;
    };
  };

  if(n!=i) list_add(&(n->children), &(self->children));

  /** Now ask n to add the rest of the word */
  n->AddWord(n, word+1, len-1, data, type);

  return;
};

VIRTUAL(TrieNode, Object)
     VMETHOD(AddWord) = TrieNode_AddWord;
END_VIRTUAL

LiteralNode LiteralNode_Con(LiteralNode self, char value) {
  self->value = value;

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

VIRTUAL(LiteralNode, TrieNode)
     VMETHOD(Con) = LiteralNode_Con;
     VMETHOD(super.__eq__) = LiteralNode_eq;
END_VIRTUAL

RootNode RootNode_Con(RootNode this) {
  TrieNode self=(TrieNode)this;
  
  INIT_LIST_HEAD(&(this->super.peers));
  INIT_LIST_HEAD(&(this->super.children));

  return this;
};

VIRTUAL(RootNode, TrieNode)
     VMETHOD(Con) = RootNode_Con;
END_VIRTUAL
