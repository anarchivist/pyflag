/**********************************************************
 * Simple Exception handling library
 *
 * Michael Cohen (scudette@users.sourceforge.net) (C) 2004
 *
 * This library provides a simple interface to exception handling, via
 * a couple of macros and a few helper functions. Following is a short
 * description of how to use this library:

 * An exception is a condition that may be raised at any point in the
 * program. The exception, when raised, bubbles through the stack and
 * looks for a handled clause. If noone handles the exception, an
 * "unhandled exception" error occurs and the program is terminated.
 
 * The advantage of using exceptions, is that error conditions may be
 * signaled from a deeply nested function to a calling function
 * without needing to rely on error information being passed together
 * with the return code of the function. An alternative error
 * signaling mechanism is useful.

 * Most modern OO languages (eg. C++,Java, Python) support
 * exceptions. In pure C exceptions are possible if wrapping the
 * set_jmp and longjmp c library calls. This is what this library
 * does.

 * Using this library is quite straight forward, e.g:
	
	#include <stdio.h>
	#include <string.h>
	#include "except.h"
	
	int multiplier(int x) {
	  if(x<0) 
	    raise(E_UNDERFLOW,"Integer too small");
	  return(x*2);
	};
	
	int testfunction(int x) {
	  if(x>2) 
	    raise(E_OVERFLOW,"Integer too big");
	  TRY {
	    return(multiplier(x));
	  } EXCEPT(E_UNDERFLOW) {
	    return(0);
	  };
	  return(0);
	};
	
	int main() {
	  int i=0;
	  
	  // This shows an example where multiple exceptions are caught at once
	  TRY {
	    while(1) {
	      printf("My answer is %u\n",testfunction(i++));
	    };
	  } EXCEPT( E_OVERFLOW,E_UNDERFLOW ) {
	    printf("Error : %s\n",except_str);
	  };
	  
	  // This shows nested exceptions
	  TRY {
	    TRY {
	      printf("My answer is %u\n",testfunction(-5));
	    } EXCEPT(E_OVERFLOW,E_UNDERFLOW) {
	      printf("Overflow occured: %s\n",except_str);    
	    };
	  } EXCEPT(E_UNDERFLOW) {
	    printf("Underflow occured %s!\n",except_str);
	  };
	
	  return(0);
	}

 *  As can be seen the TRY { } EXCEPT { }; block idiom is preserved.

 *  Note that raise allowes a caller to explain why they are raising
 *  the exception by providing a string arg. This is a variarg
 *  function that calls vsnprintf internally. Alternatively the caller
 *  can specify an arbitrary object they would like to throw as a void
 *  
 *  License:
 *  This library is available under the GPL.
 *
 *************************************************************/
/******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG  $Version: 0.80.1 Date: Tue Jan 24 13:51:25 NZDT 2006$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************/


#include <setjmp.h>
#include <stdarg.h>
#include <stdlib.h>

#ifndef EXCEPT_H
#define EXCEPT_H

#define PASS

/* This is a list of all exceptions. You can add your own here, but
   please add a string description of each exception to except.c */
enum _exception {
  ZERO,E_ANY,E_GENERIC,E_OVERFLOW,
  E_UNDERFLOW,E_IOERROR, E_NOMEMORY, E_STOPITERATION
};

//Maximum size of exception string
#define EXCEPT_BUFFER_SIZE 255
//Maximum nesting of exceptions, If you need a deeper nest, increase
//this number
#define MAXIMUM_NESTING 512

//Current depth of exception stack
extern int except_level;
extern char except_str[];
extern jmp_buf env[];
extern void *except_obj;
extern enum _exception __EXCEPT__;

//Currently raised exception. This will be cleared before doing the
//EXCEPT clause.
extern enum _exception _except;

#define TRY \
          except_level++;\
          _except=setjmp(env[except_level]);\
          if(!_except) {

#define EXCEPT(...) ;\
             };\
             except_level--;\
             if(_except && !except_cmp(_except,__VA_ARGS__,0)) \
             {\
                 except_raise(_except,NULL,NULL);\
              } else if(_except && (((__EXCEPT__=_except) && (_except=0)) || 1))

#ifdef __DEBUG__
#define RAISE except_raise
#else
#define RAISE(x, ... ) except_raise(x,NULL)
#endif

extern void except_raise(enum _exception e, void *obj, char *reason, ...);
extern int except_cmp(int e,...) ;
#endif
