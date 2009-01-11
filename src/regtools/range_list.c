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
 * $Id: range_list.c 122 2008-08-09 20:24:01Z tim $
 */

#include <math.h>
#include "range_list.h"
#include "talloc.h"

/*******************/
/* Private symbols */
/*******************/
#define RANGE_LIST_ALLOC_SIZE 256

#if 0
#include <stdio.h>
static void range_list_print(const range_list* rl)
{
  uint32_t i;
  for(i=0; i<rl->size; i++)
    fprintf(stderr, " %d=%p,%d,%d,%p", i, (void*)rl->elements[i],
	    rl->elements[i]->offset, rl->elements[i]->length, 
	    rl->elements[i]->data);
  fprintf(stderr, "\n");
}
#endif

/*
 * Inserts elem into rl at the specified index and updates rl->size. 
 * Memory reallocation of rl->elements is handled when necessary, and
 * rl->elem_alloced is updated in this case..  Returns false if memory
 * could not be allocated.  
 */
static bool range_list_insert(range_list* rl, range_list_element* elem, uint32_t index)
{
  uint32_t i;
  range_list_element** tmp;

  if(rl->size == rl->elem_alloced)
  {
    tmp = (range_list_element**)realloc(rl->elements, 
					(rl->elem_alloced+RANGE_LIST_ALLOC_SIZE)
					* sizeof(range_list_element*));
    if(tmp == NULL)
      return false;
    rl->elements = tmp;
    rl->elem_alloced += RANGE_LIST_ALLOC_SIZE;
  }

  /* Do the shuffle to the right. */
  for(i=rl->size; i > index; i--)
    rl->elements[i] = rl->elements[i-1];
  rl->elements[index] = elem;

  rl->size++;
  return true;
}

/*
 * Finds the element with the closest offset to that provided, such that
 * the element's offset <= the provided offset.  If no such element
 * exists, this returns -1 which indicates that the provided offset
 * appears before all elements.
 */
static int32_t range_list_find_previous(const range_list* rl, uint32_t offset)
{
  uint32_t h_idx, l_idx, cur_idx;
  uint32_t h_val, l_val;
  range_list_element* cur_elem;

  if((rl->size == 0) || (offset < rl->elements[0]->offset))
    return -1;

  if(offset >= rl->elements[rl->size-1]->offset)
    return rl->size-1;

  h_idx = rl->size-1;
  l_idx = 0;
  while(h_idx != l_idx)
  {
    h_val = rl->elements[h_idx]->offset + rl->elements[h_idx]->length;
    l_val = rl->elements[l_idx]->offset;
    /* Make an educated guess as to the "middle" index based on the
     * ratios of the offset and high/low values.
     */
    cur_idx = (uint32_t)ceil((((double)offset-l_val)/(h_val-l_val))*(h_idx-l_idx));
    if(cur_idx > h_idx)
      cur_idx = h_idx;
    if(cur_idx < l_idx)
      cur_idx = l_idx;
    cur_elem = rl->elements[cur_idx];

    if((offset >= cur_elem->offset) && (offset < rl->elements[cur_idx+1]->offset))
      return cur_idx;
    
    if(offset < cur_elem->offset)
      h_idx = cur_idx-1;
    else
      l_idx = cur_idx+1;
  }

  return h_idx;
}


/******************/
/* Public symbols */
/******************/
range_list* range_list_new(void *ctx)
{
  range_list* rl;

  rl = talloc(ctx, range_list);
  if(rl == NULL)
    return NULL;

  rl->elements = talloc_array(rl, range_list_element*,
			      RANGE_LIST_ALLOC_SIZE);

  if(rl->elements == NULL)
  {
    talloc_free(rl);
    return NULL;
  }

  rl->elem_alloced = RANGE_LIST_ALLOC_SIZE;
  rl->size = 0;

  return rl;
}

uint32_t range_list_size(const range_list* rl)
{
  return rl->size;
}



bool range_list_add(range_list* rl, uint32_t offset, uint32_t length, void* data)
{
  uint32_t insert_index;
  range_list_element* elem;
  range_list_element* prev_elem;
  /*fprintf(stderr, "DEBUG: rl->size=%d\n", rl->size);*/
  /* Sorry, limited to 2**31-1 elements. */
  if(rl->size >= 0x7FFFFFFF)
    return false;

  /* 0-length ranges aren't allowed. */
  if(length == 0)
    return false;
  
  /* Check for integer overflows */
  if((uint32_t)(offset+length) < offset || (uint32_t)(offset+length) < length)
    return false;

  /* Find insertion point and validate there are no overlaps */
  insert_index = range_list_find_previous(rl, offset)+1;
  
  /* Does the previous element overlap with this one? */
  if(insert_index > 0)
  {
    prev_elem = rl->elements[insert_index-1];
    if(offset < prev_elem->length + prev_elem->offset)
      return false;
  }

  /* Does this new element overlap with the next one? */
  if((insert_index+1 < rl->size) 
     && (offset+length > rl->elements[insert_index+1]->offset))
    return false;

  elem = talloc(rl, range_list_element);
  if(elem == NULL)
    return false;
  elem->offset = offset;
  elem->length = length;
  elem->data = data;
  
  if(!range_list_insert(rl, elem, insert_index))
  {
    talloc_free(elem);
    return false;
  }

  //Steal the data
  talloc_steal(elem, data);

  return true;
}


bool range_list_remove(range_list* rl, uint32_t index)
{
  uint32_t i;
  range_list_element** tmp;

  if(index >= rl->size)
    return false;

  talloc_free(rl->elements[index]);

  /* Do the shuffle to the left. */
  for(i=index; i < (rl->size-1); i++)
    rl->elements[i] = rl->elements[i+1];
  rl->elements[rl->size-1] = NULL;
  rl->size--;

  /* Try to keep memory usage down */
  if(rl->size + 2 * RANGE_LIST_ALLOC_SIZE  < rl->elem_alloced)
  {
    tmp = (range_list_element**)talloc_realloc_size(rl, rl->elements, 
						    (rl->elem_alloced-2*RANGE_LIST_ALLOC_SIZE)
						    * sizeof(range_list_element*));
    if(tmp != NULL)
    {
      rl->elements = tmp;
      rl->elem_alloced -= 2*RANGE_LIST_ALLOC_SIZE;
    }
  }

  return true;
}


const range_list_element* range_list_get(const range_list* rl, uint32_t index)
{
  if(index >= rl->size)
    return NULL;

  return rl->elements[index];
}


int32_t range_list_find(const range_list* rl, uint32_t offset)
{
  uint32_t prev_idx;
  range_list_element* elem;

  if((offset < rl->elements[0]->offset)
     || (offset > rl->elements[rl->size-1]->offset 
	 + rl->elements[rl->size-1]->length))
    return -1;

  prev_idx = range_list_find_previous(rl, offset);
  elem = rl->elements[prev_idx];
  if(offset < elem->offset+elem->length)
    return prev_idx;

  return -2;
}


void* range_list_find_data(const range_list* rl, uint32_t offset)
{
  int32_t index = range_list_find(rl, offset);
  if(index < 0)
    return NULL;

  return rl->elements[index]->data;
}


bool range_list_split_element(range_list* rl, uint32_t index, uint32_t offset)
{
  range_list_element* cur_elem;
  range_list_element* new_elem;

  if(index >= rl->size)
    return false;

  cur_elem = rl->elements[index];
  if((offset <= cur_elem->offset) 
     || (offset >= cur_elem->offset+cur_elem->length))
    return false;

  new_elem = talloc(rl, range_list_element);
  if(new_elem == NULL)
    return false;
  
  new_elem->offset = offset;
  new_elem->length = cur_elem->offset + cur_elem->length - offset;
  new_elem->data = cur_elem->data;
  
  if(!range_list_insert(rl, new_elem, index+1))
  {
    talloc_free(new_elem);
    return false;
  }

  cur_elem->length = new_elem->offset - cur_elem->offset;

  return true;
}


bool range_list_has_range(range_list* rl, uint32_t start, uint32_t length)
{
  int32_t idx1, idx2;

  idx1 = range_list_find(rl, start);
  if(idx1 < 0)
    return false;

  idx2 = range_list_find(rl, start+length);
  if(idx2 < 0)
    return false;

  if(idx1 == idx2)
    return true;

  while(idx1 != idx2)
  {
    if(rl->elements[idx1]->offset + rl->elements[idx1]->length 
       != rl->elements[idx1+1]->offset)
      return false;
    idx1++;
  }

  return true;
}
