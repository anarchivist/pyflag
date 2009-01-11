/*
 * This is a really simple implementation of a stack which stores chunks
 * of memory of any type.  It still needs work to eliminate memory
 * leaks. 
 *
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
 * $Id: void_stack.c 111 2008-05-01 04:06:22Z tim $
 */

#include "void_stack.h"
#include "talloc.h"

void_stack* void_stack_new(void *ctx, unsigned short max_size)
{
  void_stack* ret_val = talloc(ctx, void_stack);

  if(!ret_val) return NULL;
  
  ret_val->elements = talloc_array(ret_val, void *,max_size);
  if (ret_val->elements == NULL)
    goto error;

  ret_val->max_size = max_size;
  ret_val->top = 0;

  return ret_val;
 error:
  talloc_free(ret_val);
  return NULL;
}


void_stack* void_stack_copy(void_stack* v)
{
  void_stack* ret_val;
  if(v == NULL)
    return NULL;

  ret_val = void_stack_new(v, v->max_size);
  if(ret_val == NULL)
    return NULL;

  memcpy(ret_val->elements, v->elements, v->top * sizeof(void*));
  ret_val->top = v->top;

  return ret_val;
}


void_stack* void_stack_copy_reverse(void_stack* v)
{
  unsigned int i;
  void_stack* ret_val;
  if(v == NULL)
    return NULL;

  ret_val = void_stack_new(v,v->max_size);
  if(ret_val == NULL)
    return NULL;

  for(i = 0; i < v->top; i++)
    ret_val->elements[i] = v->elements[v->top-i-1];
  ret_val->top = v->top;

  return ret_val;
}


unsigned short void_stack_size(const void_stack* stack)
{
  return stack->top;
}


/** The returned element is stolen to context ctx */
void* void_stack_pop(void *ctx, void_stack* stack)
{
  void* ret_val = NULL;

  if(stack->top > 0)
  {
    ret_val = stack->elements[stack->top];
    stack->elements[stack->top] = NULL;
    stack->top--;
  }

  talloc_steal(ctx, ret_val);
  return ret_val;
}

/** The stack takes ownership of e */
bool void_stack_push(void_stack* stack, void* e)
{
  if(stack->top < stack->max_size)
  {
    stack->top ++;
    stack->elements[stack->top] = e;
    talloc_steal(stack, e);
    return true;
  }
  else
    return false;
}

/** Stack retains ownership of the returned pointer */
const void* void_stack_cur(const void_stack* stack)
{
  void* ret_val = NULL;

  if(stack->top > 0)
    ret_val = stack->elements[stack->top];

  return ret_val;
}


void_stack_iterator* void_stack_iterator_new(void *ctx, 
					     const void_stack* stack)
{
  void_stack_iterator* ret_val = NULL;
  
  if(stack != NULL)
  {
    ret_val = talloc(ctx, void_stack_iterator);
    if (ret_val != NULL)
    {
      ret_val->stack = stack;
      ret_val->cur = 0;
    }
  }

  return ret_val;
}


const void* void_stack_iterator_next(void_stack_iterator* iter)
{
  if(iter->cur < iter->stack->top) {
    iter->cur++;
    return iter->stack->elements[iter->cur];
  } else
    return NULL;
}
