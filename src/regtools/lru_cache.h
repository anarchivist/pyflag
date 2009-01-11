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
 * $Id: lru_cache.h 122 2008-08-09 20:24:01Z tim $
 */

#ifndef LRU_CACHE_H
#define LRU_CACHE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "list.h"

struct lru_cache_element;
typedef struct lru_cache_element lru_cache_element; 

/** Each element belongs to two lists simultaneously - the hash lists
    are lists that hang off the main hash table, while "list" is an
    ordered list of elements. The list is ordered in the sense that
    new objects are added to the tail, and expired objects are removed
    from the head. 
*/
struct lru_cache_element
{
  void* index;
  uint32_t index_len;
  void* data;
  struct list_head hash;
  struct list_head list;
};

typedef struct _lru_cache
{
  uint32_t secret;
  uint32_t num_keys;
  uint32_t num_buckets;
  uint32_t max_keys;
  lru_cache_element sorted;
  lru_cache_element** table;
  bool free_data;
} lru_cache;


lru_cache* lru_cache_create(void *ctx, uint32_t max_keys, uint32_t secret, bool free_data);

/* Returns a pointer to the old, replaced data stored at index.  
 * Returns NULL if no entry was overwritten.
 */
bool lru_cache_update(lru_cache* ht, const void* index, 
		      uint32_t index_len, void* data);

/* Returns pointer to data previously stored at index.
 * If no data was found at index, NULL is returned.
 */
void* lru_cache_find(lru_cache* ht, const void* index, 
		     uint32_t index_len);

/* Removes entry from table at index.
 * Returns pointer to data that was there previously.  
 * Returns NULL if no entry is at index.
 */
bool lru_cache_remove(lru_cache* ht, const void* index, 
		      uint32_t index_len);

#endif
