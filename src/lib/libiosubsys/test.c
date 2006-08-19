#include "libiosubsys.h"

int main() {
  IOOptions opts = CONSTRUCT(IOOptions, IOOptions, add, NULL, NULL, NULL, NULL);
  IOSource io;
  char buf[2550];
  int len;

  CONSTRUCT(IOOptions, IOOptions, add, opts, opts, "filename", "passwd.e01");
  
  io = CONSTRUCT(EWFIOSource, IOSource, super.Con, opts, opts);
  if(!io) { 
    printf("%s",_error_buff);
    return -1;
  };
  len = io->read_random(io, buf, 2500, 1000);

  buf[len]=0;
  printf("contents %s" , buf);
  
  talloc_free(opts);

  return 1;
};
