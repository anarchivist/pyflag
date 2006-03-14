/*******************************************
   This is an implementation of a hash table 
*******************************************/
#include "hashtable.h"
#include "misc.h"

HashTable HashTable_Con(HashTable self, int hash_size) {
  int i;
  
  self->hash_size = hash_size;
  self->mask = (1 << self->hash_size -1);

  self->slots = (struct hash_item *)talloc_size(self, 
	  (sizeof(struct hash_item) * (1 << self->hash_size)));

  /** initialise our lists */
  for(i=0;i<HASH_SIZE; i++) {
    INIT_LIST_HEAD(&(self->slots[i].list));
  };

  return self;
};

static int remove_from_list(void *data) {
  struct hash_item *item = (struct hash_item *)data;

  list_del(&(item->list));

  return 0;
};

void HashTable_Put(HashTable self, char *key, int length, void *data) {
  struct hash_item *item=talloc(self, struct hash_item);

  int hash = CALL(self,hash_function, key, length) & HASH_SIZE;
  
  /** Add the item to the tail of the slot */
  list_add_tail(&item->list, &(self->slots[hash].list));
  
  /** When the item is destroyed we maintain the list integrity */
  talloc_set_destructor(item, remove_from_list);
};

struct hash_item *HashTable_Get(HashTable self, char *key, int length) {
  int hash = self->hash_function(self, key, length);
  struct hash_item *i;

  list_for_each_entry(i, &(self->slots[hash].list), list) {
    if(!memcmp(key, i->key, length))
      return i;
  };
  
  return NULL;
};

void HashTable_Del(HashTable self, char *key, int length) {
  talloc_free(self->Get(self, key, length));
};

int HashTable_hash_function(HashTable self, char *key, int length) {
  /* Default hash function uses the first HASH_SIZE bits of the
     key. This is bad... you need to improve on that 
  */
  if(length > self->hash_size/8)
    return *(int *)key & self->mask;
  
  else return 0;

};

VIRTUAL(HashTable, Object)
     VMETHOD(Con) = HashTable_Con;
     VMETHOD(Put) = HashTable_Put;
     VMETHOD(Get) = HashTable_Get;
     VMETHOD(Del) = HashTable_Del;
     VMETHOD(hash_function) = HashTable_hash_function;
END_VIRTUAL

/** Test this module */
MODULE_INIT(hashtables) {
  HashTable h=CONSTRUCT(HashTable, HashTable, Con, 8, NULL);
};
