/*******************************************************
     This is an implementation of a simple hash table.
*******************************************************/
#ifndef __HASHTABLE_H
#define __HASHTABLE_H

#include "class.h"
#include "list.h"
#include "talloc.h"

#define HASH_SIZE 0xFF

struct hash_item {
  char *key;
  void *data;
  struct list_head list;
};

CLASS(HashTable, Object)
/** Number of bits in the hash */
     unsigned int hash_size;
     unsigned int mask;

     struct hash_item *slots;

     HashTable METHOD(HashTable, Con, int hash_number_of_bits);

/** Store the data in a new hash_item in the hash */
     void METHOD(HashTable, Put, char *key, int length, void *data);

/** Retrieve a hash table entry - items can be deleted by calling
    talloc_free of the retrieved item too. 
*/
     struct hash_item *METHOD(HashTable, Get, char *key, int length);

/** Allows us to delete items from the hash table */
     void METHOD(HashTable, Del, char *key, int length);

/** This can be over ridden depending on what makes sense for the data */
     int METHOD(HashTable, hash_function, char *key, int length);
END_CLASS

#endif
