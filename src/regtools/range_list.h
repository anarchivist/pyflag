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
 * $Id: range_list.h 122 2008-08-09 20:24:01Z tim $
 */

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifndef _RANGE_LIST_H
#define _RANGE_LIST_H


typedef struct _range_list_element
{
  uint32_t offset;
  uint32_t length;
  void* data;
} range_list_element;


typedef struct _range_list
{
  range_list_element** elements;
  uint32_t elem_alloced;
  uint32_t size;
} range_list;


/* range_list_new(): 
 *  Allocates a new range_list.
 *
 * Returns: 
 *  A newly allocated range_list, or NULL if an error occurred.
 */
range_list* range_list_new();


/* range_list_free(): 
 *  Frees the memory associated with a range_list, including the elements, but
 *  not any data parameters referenced by those elements.  If rl is NULL, does
 *  nothing.
 *
 * Arguments:
 *  rl -- the range_list to be free()d.
 */
void range_list_free(range_list* rl);


/* range_list_size(): 
 *  Query the current number of elements on a range_list
 *
 * Arguments:
 *  rl -- the range_list to query
 *
 * Returns:
 *  The number of elements currently in the list.
 */
uint32_t range_list_size(const range_list* rl);


/* range_list_add():
 *  Adds an element to the range_list.  
 *  The new element must not overlap with others.
 *  NOTE: this is a slow operation.
 *
 * Arguments:
 *  rl     -- the range list to update
 *  offset -- the starting point for the range
 *  length -- the length of the range
 *  data   -- misc data associated with this range element
 * Returns:
 *  true on success, false on failure.
 *  Failures can occur due to memory limitations, max_size limitations,
 *  or if the submitted range overlaps with an existing element.  Other
 *  errors may also be possible.
 */
bool range_list_add(range_list* rl, uint32_t offset, uint32_t length, void* data);


/* range_list_remove():
 *  Removes an element from the list.  The element data structure will be 
 *  freed, but the data property will not be.
 *
 * Arguments:
 *  rl     -- the range_list to modify
 *  index  -- the element index to remove
 *
 * Returns:
 *  true if the element was successfully removed, false otherwise.
 */
bool range_list_remove(range_list* rl, uint32_t index);


/* range_list_get():
 *  Retrieves the element for a given index.
 *
 * Arguments:
 *  rl    -- the range_list being queried.
 *  index -- the element index desired.
 * 
 * Returns:
 *  The element for a given index, or NULL if the element is not available.
 */
const range_list_element* range_list_get(const range_list* rl, uint32_t index);


/* range_list_find():
 *  Attempts to find the unique element whose range encompasses offset.
 *
 * Arguments:
 *  rl     -- the range_list being queried.
 *  offset -- the location for which an element is desired.
 *
 * Returns:
 *  A matching element index or a negative value if none could be found.
 */
int32_t range_list_find(const range_list* rl, uint32_t offset);


/* range_list_find_data():
 *  Same as range_list_find(), but returns the data associated with an element.
 *
 * Arguments:
 *  rl     -- the range_list being queried.
 *  offset -- the address to search for in the ranges
 *
 * Returns:
 *  The data element of the matching element index or NULL if none could
 *  be found.
 *
 *  NOTE: May also return NULL if an element matched but if the data
 *        element was never set.
 */
void* range_list_find_data(const range_list* rl, uint32_t offset);


/* range_list_split_element():
 *  Splits an existing element into two elements in place.
 *
 *  The resulting list will contain an additional element whose offset 
 *  is the one provided and whose length extends to the end of the old element
 *  (the one identified by the index).  The original element's offset will 
 *  remain the same while it's length is shortened such that it is contiguous
 *  with the newly created element.  The newly created element will have an index 
 *  of one more than the current element.
 *
 *  Both the original element and the newly created element will reference the 
 *  original element's data.
 *
 * Arguments:
 *  rl     -- the range_list to modify
 *  index  -- the index of the element to be split
 *  offset -- the at which the element will be split
 *
 * Returns:
 *  true if the element was successfully split, false otherwise.
 *   
 *
 */
bool range_list_split_element(range_list* rl, uint32_t index, uint32_t offset);


/* range_list_has_range():
 *  Determines whether or not a specified range exists contiguously within the
 *  range_list.
 *
 * Arguments:
 *  rl     -- the range_list to search
 *  start  -- the offset at the beginning of the range
 *  length -- the length of the range
 *
 * Returns:
 *  true if the specified range exists and is complete, false otherwise.
 */
bool range_list_has_range(range_list* rl, uint32_t start, uint32_t length);

#endif
