/****************************************
    Library defining simple exception handling.
**************************************/
#include "except.h"
#include <stdio.h>

#ifdef __DEBUG__
static char *_exception_descriptions[] = {"No Error","Exception","Generic Error","Overflow Error","Underflow Error","IO Error","Out of Memory Error", "Stop Iteration"};
#endif

int except_cmp(int e,...) 
{
  int s;
  va_list ap;
  va_start(ap, e);
  do {
    s=va_arg(ap,int);
    // We matched the exception thrown, or the user asked for E_ANY
    if(s==e || s==E_ANY) return(1);
  } while(s);
  va_end(ap);
  return(0);
};

//Current depth of exception stack
int except_level=0;
char except_str[EXCEPT_BUFFER_SIZE];
jmp_buf env[MAXIMUM_NESTING];
enum _exception __EXCEPT__;

//Currently raised exception. This will be cleared before doing the EXCEPT clause.
enum _exception _except;

/* Raises an exception throught the stack */
#ifdef __DEBUG__
void except_raise(enum _exception e,char *reason, ...) {
  if(reason) {
    va_list ap;
    va_start(ap, reason);
    vsnprintf(except_str,EXCEPT_BUFFER_SIZE-1,reason,ap);
    va_end(ap);
  };

  //Terminate the process if this exception is unhandled:
  if(except_level==0) {
    fprintf(stderr,"Unhandled Exception(%s): %s\n",_exception_descriptions[e],except_str);
    exit(-1);
  };
  longjmp(env[except_level],e);
};

#else
void except_raise(enum _exception e,char *reason, ...) {
  longjmp(env[except_level],e);
};
#endif
