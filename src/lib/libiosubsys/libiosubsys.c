#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include "list.h"

#include "misc.h"
#include "class.h"
#include "libiosubsys.h"

IOSource IOSource_Con(IOSource self, IOOptions opts) {
  char *name = CALL(opts, get_value, "filename");

  // If we dont get a filename, we assume the first option is it
  if(!name) {
    list_next(opts, &(opts->list), list);
    if(opts) name = opts->name;
  };

  if(name) {
    self->fd = open(name,O_RDONLY);

    /** We failed to open the file */
    if(self->fd<0) {
      talloc_free(self);
      return NULL;
    };
  };

  return self;
};

int IOSource_read_random(IOSource self, char *buf, uint32_t len, uint64_t offs) {
  lseek(self->fd, offs,0);

  return read(self->fd, buf, len);
};

VIRTUAL(IOSource, Object)
     VATTR(name) = "Standard";
     VATTR(description) = "Standard IO source";

     VMETHOD(Con) = IOSource_Con;
     VMETHOD(read_random) = IOSource_read_random;
END_VIRTUAL


IOOptions IOOptions_add(IOOptions self, IOOptions list, char *name, char *value) {

  if(list) {
    self->name = talloc_strdup(self, name);
    self->value = talloc_strdup(self,value);

    list_add_tail(&(self->list), &(list->list));
  } else {
    INIT_LIST_HEAD(&(self->list));
  };

  return self;
};

char *IOOptions_get_value(IOOptions self, char *name) {
  IOOptions i;

  list_for_each_entry(i, &(self->list), list) {
    if(!strcmp(name, i->name)) return i->value;
  };

  return NULL;
};


VIRTUAL(IOOptions, Object)
     VMETHOD(add) = IOOptions_add;
     VMETHOD(get_value) = IOOptions_get_value;
END_VIRTUAL
