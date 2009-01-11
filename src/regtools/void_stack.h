/*
 * Copyright (C) 2005,2007 Timothy D. Morgan
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
 * $Id: void_stack.h 111 2008-05-01 04:06:22Z tim $
 */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#ifndef _VOID_STACK_H
#define _VOID_STACK_H

typedef struct _void_stack
{
  void** elements;
  unsigned short max_size;
  unsigned short top;
} void_stack;

typedef struct _void_stack_iterator
{
  const void_stack* stack;
  unsigned short cur;
} void_stack_iterator;


/* void_stack_new(): 
 *  Allocates a new void_stack.
 *
 * Arguments:
 *  max_size -- the maxiumum number of elements 
 *              which may be pushed onto the stack.
 *
 * Returns: 
 *  a pointer to the newly allocated void_stack, or NULL if an error occurred.
 */
void_stack* void_stack_new(void *ctx, unsigned short max_size);


/* void_stack_copy(): 
 *  Makes a shallow copy of void_stack.
 *
 * Arguments:
 *  v -- the stack to make a copy of.
 *
 * Returns:
 *  a pointer to the duplicate void_stack, or NULL If an error occurred.
 */
void_stack* void_stack_copy(void_stack* v);


/* void_stack_copy_reverse(): 
 *  Makes a shallow copy of void_stack in reverse order.
 *
 * Arguments:
 *  v -- the stack to make a copy of.
 *
 * Returns:
 *  a pointer to the duplicate void_stack (which will be in reverse order),
 *  or NULL If an error occurred.
 */
void_stack* void_stack_copy_reverse(void_stack* v);


/* void_stack_size(): 
 *  Query the current number of elements on a void_stack()
 *
 * Arguments:
 *  stack -- the void_stack to query
 *
 * Returns:
 *  the number of elements currently on the stack.
 */
unsigned short void_stack_size(const void_stack* stack);


/* void_stack_pop():
 *  Removes the top element on a void_stack and returns a reference to it.
 *
 * Arguments:
 *  stack -- the void_stack to pop
 *
 * Returns:
 *  a pointer to the popped stack element, or NULL if no elements exist on 
 *  the stack.
 */
void* void_stack_pop(void *ctx, void_stack* stack);


/* void_stack_push():
 *  Puts a new element on the top of a void_stack.
 *
 * Arguments:
 *  stack -- the void_stack being modified.
 *
 *  e     -- the element to be added
 *
 * Returns:
 *  true if the element was successfully added, false otherwise.
 */
bool void_stack_push(void_stack* stack, void* e);


/* void_stack_cur():
 *  Returns a pointer to the current element on the top of the stack.
 *
 * Arguments:
 *  stack -- the void_stack being queried.
 *
 * Returns:
 *  a pointer to the current element on the top of the stack, or NULL if no
 *  elements exist in the stack.
 */
const void* void_stack_cur(const void_stack* stack);


/* void_stack_iterator_new():
 *  Creates a new iterator for the specified void_stack.
 *
 * Arguments:
 *  stack -- the void_stack to be referenced by the new iterator
 *
 * Returns:
 *  a new void_stack_iterator, or NULL if an error occurred.
 */
void_stack_iterator* void_stack_iterator_new(void *ctx, const void_stack* stack);


/* void_stack_iterator_next():
 *  Returns a pointer to the the next element in the stack.  Iterates over 
 *  elements starting in order from the oldest element (bottom of the stack).
 *
 * Arguments:
 *  iter -- the void_stack_iterator used to lookup the next element.
 *
 * Returns:
 *  a pointer to the next element.
 */
const void* void_stack_iterator_next(void_stack_iterator* iter);


/* XXX: for completeness, might want to add a void_stack_iterator_first()
 *      function, to return iterator to first element
 */
#endif
