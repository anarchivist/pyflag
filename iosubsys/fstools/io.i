%module iosubsys
%include cstring.i
%include exception.i
%cstring_output_withsize(char *buf, int *len);
%{
#include "fs_tools.h"
#include "fs_io.h"
#include "except.h"
  
  /* These functions are wrapped in order to ensure we trap C exceptions and emit SWIG exceptions for python */

  int parse_options(IO_INFO *io,char *opts) {
    TRY {
      io_parse_options(io,opts);
    } EXCEPT(E_ANY) {
      return(- __EXCEPT__);
    };
    return(0);
  };

  IO_INFO *Open(char *name) {
    IO_INFO *result;
    TRY {
      result=io_open(name);
    } EXCEPT(E_ANY) {
      return((IO_INFO *) __EXCEPT__);
    };
    return(result);
  };

  int read_random(IO_INFO *self, char *buf, int *len, long  long int offs) {
    int result;
    TRY {
      result=self->read_random(self,buf,*len,offs,"Python calling");
      *len=result;
    } EXCEPT(E_ANY) {
      return(-__EXCEPT__);
    };

    return(result);
  };

  /* A simple switch that returns the swig exception given our exceptions in except.h */
  int map_exceptions_for_swig(enum _exception e) {
    switch(e) {
    case E_OVERFLOW:
      return(SWIG_OverflowError);
    case E_IOERROR:
      return(SWIG_IOError);
    case E_NOMEMORY:
      return(SWIG_MemoryError);
    case E_GENERIC:
    case E_ANY:
    default:
      return (SWIG_UnknownError);
    };
  };

%}


%exception parse_options {
  $action
    if(result<0) {
      SWIG_exception(map_exceptions_for_swig(-result),except_str);
    };
}

%exception Open {
  $action
    if(((unsigned int)result)<20) {
      SWIG_exception(map_exceptions_for_swig((enum _exception)result),except_str);
    };
}

%exception read_random {
  $action
    if(result<0) {
      SWIG_exception(map_exceptions_for_swig(-result),except_str);
    };
}

IO_INFO *Open(char *name);
IO_INFO *io_open(char *name);
int read_random(IO_INFO *self, char *buf, int *len, long long  int offs);
int parse_options(IO_INFO *io,char *opts) ;
void io_help(char *name);
int io_close(IO_INFO *self);
