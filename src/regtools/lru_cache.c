/*
 * Copyright (C) 2008 Timothy D. Morgan
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  
 *
 * $Id: lru_cache.c 122 2008-08-09 20:24:01Z tim $
 */

#include "../include/lru_cache.h"
#include "talloc.h"

#define LRU_CACHE_DEBUG 0

/* XXX: really should replace this with a real universal hash or other
 *      fast HMAC.
 */ 
static uint32_t lru_cache_compute_hash(uint32_t num_buckets,
				       uint32_t secret,
				       const void* buf,
				       uint32_t buf_len)
{
  uint32_t i;
  uint32_t ret_val = 0x243f6a88;
  unsigned char* s = (unsigned char*)&secret;
  const unsigned char* b = (unsigned char*)buf;

  for(i=0; i<buf_len; i++)
    ret_val = (ret_val+(i^s[i%4])*b[i]) % num_buckets;
  
  return ret_val;
}

/* Returns approximately floor(log_2(n)) (log base 2 of n, floored) 
 * If n == 0, returns 0
 */
static uint32_t lru_cache_floor_log2(uint32_t n)
{
  uint32_t ret_val;
  
  for(ret_val=31; ret_val > 1; ret_val--)
    if((n & (1 << ret_val)) != 0)
      return ret_val;

  return 0;
}

#if 0
static void lru_cache_print(lru_cache* ht)
{
  uint32_t i;
  lru_cache_element* cur;

  printf("from newest to oldest:\n");
  for(cur=ht->newest; cur != NULL; cur=cur->older)
  {
    /*    write(STDOUT_FILENO, cur->index, cur->index_len);*/
    printf("%p", (void*)cur);
    printf("\n");
    if(cur->older == ht->newest)
    {
      printf("??? Loop in LRU list!!");
      break;
    }
  }
  printf("\n");

  printf("table:\n");
  for(i=0; i<ht->num_buckets; i++)
  {
    printf("%.8X: ", i);
    for(cur=ht->table[i]; cur != NULL; cur=cur->next)
    {
      /*      write(STDOUT_FILENO, cur->index, cur->index_len);*/
      printf("%p", (void*)cur);
      printf("|");

      if(cur->next == ht->table[i])
      {
	printf("??? Loop in table chain!!");
	break;
      }
    }
    printf("\n");
  }
}
#endif

lru_cache* lru_cache_create(void *ctx, uint32_t max_keys, uint32_t secret, bool free_data)
{
  lru_cache* ret_val;
  int i;
  
  ret_val = talloc(ctx, lru_cache);
  if(ret_val == NULL)
    return NULL;

  if(max_keys == 0)
    ret_val->num_buckets = 2048;
  else
  {
    ret_val->num_buckets = max_keys/lru_cache_floor_log2(max_keys);
    if(ret_val->num_buckets < 1)
      ret_val->num_buckets = 1;
  }

  ret_val->table = talloc_array(ret_val, lru_cache_element*, 
				ret_val->num_buckets); 
  if(ret_val->table == NULL)
    goto error;

  /* Initialise all the list heads */
  for(i=0;i<ret_val->num_buckets;i++) {
    ret_val->table[i] = talloc(ret_val->table, lru_cache_element);
    INIT_LIST_HEAD(&ret_val->table[i]->hash);
  };
  
  INIT_LIST_HEAD(&ret_val->sorted.list);
  ret_val->max_keys = max_keys;
  ret_val->secret = secret;
  ret_val->free_data = free_data;
  ret_val->num_keys = 0;

  return ret_val;
 error:
  talloc_free(ret_val);
  return NULL;
}

bool lru_cache_update(lru_cache* ht, const void* index, 
		      uint32_t index_len, void* data)
{
  uint32_t hash;
  lru_cache_element *i;
  lru_cache_element* e = NULL;

  hash = lru_cache_compute_hash(ht->num_buckets, ht->secret, index, index_len);
  list_for_each_entry(i, &ht->table[hash]->hash, hash) {
    if((index_len == i->index_len) 
       && memcmp(i->index, index, index_len) == 0)
      { 
	e = i;
	break;
      }
  }
  
  if(e != NULL)
  { /* We found the index, so we're going to overwrite the data.
     * We also need to reposition the element to the newest position,
     * so remove it from the list for now.
     */
    if(ht->free_data)
      talloc_free(e->data);

    // Remove from the sorted list
    list_del(&e->list);

  }
  else
  { /* We didn't find an identical index. */ 

    // No more room in the cache - reuse the oldest one:
    if((ht->max_keys != 0) && (ht->num_keys >= ht->max_keys))
    { 
      // The oldest element is at the head of the list
      list_next(e, &ht->sorted.list, list);

      // Remove from both the sorted lists and the hash table
      list_del(&e->list);
      list_del(&e->hash);

      // Possibly free its data
      if(ht->free_data)
	talloc_free(e->data);
    }
    else
    { /* Brand new element because we have room to spare. */
      e = talloc(ht->table, lru_cache_element);
      if(e == NULL)
	return false;
      
      e->index = talloc_size(e,index_len);
      if(e->index == NULL)
      {
	talloc_free(e);
	return false;
      }
      
      /* New entry, increment counters. */
      ht->num_keys++;
    }
    memcpy(e->index, index, index_len);
    e->index_len = index_len;

    /* Insert at beginning of chain, in a vaguely LRU style */
    list_add(&e->hash, &ht->table[hash]->hash);
  }
  e->data = data;

  /* Finally, let's insert the element to the newest position in the LRU list.*/
  // Add the element to the tail of the sorted lists (newest members
  // are at the tail)
  list_add_tail(&e->list, &ht->sorted.list);

  return true;
}


void* lru_cache_find(lru_cache* ht, const void* index,
		     uint32_t index_len)
{
  uint32_t hash;
  lru_cache_element* cur, *e=NULL;

  hash = lru_cache_compute_hash(ht->num_buckets, ht->secret, index, index_len);
  list_for_each_entry(cur, &ht->table[hash]->hash, hash) {
    if((index_len == cur->index_len)
       && memcmp(cur->index, index, index_len) == 0)
      { e=cur;
	break; 
      }
  }
  
  if(e)
  { /* Need to move this element up to the newest slot. */
    list_del(&e->list);
    list_add(&e->list, &ht->sorted.list);
  };

  if(e != NULL)
    return e->data;
  else
    return NULL;
}



bool lru_cache_remove(lru_cache* ht, const void* index, 
		      uint32_t index_len)
{
  uint32_t hash;
  lru_cache_element* cur, *e=NULL;

  hash = lru_cache_compute_hash(ht->num_buckets, ht->secret,
				index, index_len);

  list_for_each_entry(cur, &ht->table[hash]->hash, hash) {
    if((index_len == cur->index_len)
       && memcmp(cur->index, index, index_len) == 0)
      { e=cur;
	break; 
      }
  };

  if(e == NULL)
    return false;

  if(ht->free_data)
    talloc_free(cur->data);

  /* Detach from list */
  list_del(&e->list);
  list_del(&e->hash);

  // Free it:
  talloc_free(e);

  /* Removing entry, decrement counters. */
  ht->num_keys--;
  
  return true;
}
