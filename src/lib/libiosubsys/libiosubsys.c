#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include "list.h"
#include "misc.h"
#include "class.h"
#include "libiosubsys.h"
#include "except.h"
#include "../sgzlib.h"
#include "../libewf/libewf.h"

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

/** We remove used options from the list so we can tell if we used up
    all the options 
*/
char *IOOptions_get_value(IOOptions self, char *name) {
  IOOptions i,j;

  list_for_each_entry_safe(i,j, &(self->list), list) {
    if(!strcmp(name, i->name)) {
      // We wont bother freeing it here because talloc will do it when
      // we free the whole list.
      list_del(&i->list);
      return i->value;
    };
  };

  return NULL;
};

VIRTUAL(IOOptions, Object)
     VMETHOD(add) = IOOptions_add;
     VMETHOD(get_value) = IOOptions_get_value;
END_VIRTUAL

/** Standard IO Source */

// This destructor will be called automatically when the memory is freed
int IOSource_Destructor(void *this) {
  IOSource self = (IOSource)this;
  if(self->fd>0)
    close(self->fd);

  return 0;
};

IOSource IOSource_Con(IOSource self, IOOptions opts) {
  char *name = CALL(opts, get_value, "filename");

  // If we dont get a filename, we assume the first option is it
  if(!name) {
    talloc_free(self);
    return raise_errors(EIOError, "No filename specified!");
  };

  self->filename = talloc_strdup(self,name);
  self->fd = open(name,O_RDONLY);

  /** We failed to open the file */
  if(self->fd<0) {
    talloc_free(self);
    return raise_errors(EIOError, "Unable to open file %s\n", name);
  };

  // Find out the size of the file:
  self->size = lseek(self->fd, 0, SEEK_END);

  talloc_set_destructor((void *)self,IOSource_Destructor);
  return self;
};

int IOSource_read_random(IOSource self, char *buf, uint32_t len, uint64_t offs) {
  lseek(self->fd, offs, SEEK_SET);

  return read(self->fd, buf, len);
};

VIRTUAL(IOSource, Object)
     VATTR(name) = "standard";
     VATTR(fd) = -1;
     SET_DOCSTRING("Standard IO Source:\n\n"
		   "This is basically a pass through driver.\n\n"
		   "filename - The filename to open (just 1)\n");
     VMETHOD(Con) = IOSource_Con;
     VMETHOD(read_random) = IOSource_read_random;
END_VIRTUAL


/*** Advanced IO Source */

struct split_file {
     char *name;
     int fd;
     uint64_t start_offset;
     uint64_t end_offset;
};

int AdvIOSource_Destructor(void *this) {
  AdvIOSource self = (AdvIOSource) this;

  struct split_file *temp=(struct split_file *)(self->buffer->data);
  int i;

  for(i=0; i<self->number; i++) {
    close(temp[i].fd);
  };

  return 0;
};

IOSource AdvIOSource_Con(IOSource self, IOOptions opts) {
  AdvIOSource this=(AdvIOSource) self;
  struct split_file temp;
  IOOptions t,tt;
  uint64_t last_max_length=0;

  this->number =0;
  this->buffer=CONSTRUCT(StringIO, StringIO, Con, self);

  /** Use the opts to build our internal list of offsets. This is an
      array rather than a linked list for performance reasons. 
  **/
  list_for_each_entry_safe(t,tt, &(opts->list), list) {
    if(!strcmp("offset",t->name)) {
      // Delete items as we consume them
      list_del(&t->list);
      this->offset = parse_offsets(t->value);
      if(this->offset<0) {
	talloc_free(self);
	return raise_errors(EIOError, "Invalid argument");
      };
    }
    else if(!strcmp("filename",t->name)) {
      off_t i;

      list_del(&t->list);
      temp.name = talloc_strdup(self,t->value);
      temp.fd = open(temp.name, O_RDONLY);
      if(temp.fd<0) {
	talloc_free(self);
	return raise_errors(EIOError, "Unable to open file %s\n", temp.name);
      };

      temp.start_offset = last_max_length;
      i = lseek(temp.fd,0,SEEK_END);
      if(i<0) {
	talloc_free(self);
	return raise_errors(EIOError, "Unable to seek in file %s\n", temp.name);

	// Zero length file:
      }else if(i==0) continue;

      last_max_length+=i;
      temp.end_offset = last_max_length;

      /** Now save the information: */
      CALL(this->buffer, write, (char *)&temp, sizeof(temp));
      this->number++;
    };
  };

  if(this->buffer->size == 0 ) {
    talloc_free(self);
    return raise_errors(EIOError, "No files specified");
  };

  // Done.
  self->size = last_max_length;
  talloc_set_destructor((void *)self, AdvIOSource_Destructor);
  return self;
};

/** We read random data from the files: */
int AdvIOSource_read_random(IOSource self, char *buf, uint32_t len, uint64_t offs) {
  AdvIOSource this = (AdvIOSource) self;
  struct split_file *temp=(struct split_file *)this->buffer->data;
  int i;
  uint64_t total=0;

  /** add the offset */
  offs += this->offset;

  /** First check if the offset is too much: */
  if(offs>self->size) return 0;

  /** We need to work out which file it is - this could be a binary
      search but for now its linear. 
  */
  for(i=0; i<this->number && len>0; i++) {
    if(temp[i].start_offset <= offs && offs < temp[i].end_offset) {
      // The number of bytes available within this chunk
      uint64_t available = temp[i].end_offset-offs;
      // The amount of data to read - len is how much is required.:
      uint64_t length = min(available,len);

      // The amount of data available from this chunk.
      lseek(temp[i].fd, offs - temp[i].start_offset, SEEK_SET);
      read(temp[i].fd, buf, length);
      offs += length;
      buf += length;
      len -= length;
      total += length;
    };
  };

  return total;
}

VIRTUAL(AdvIOSource, IOSource)
     VATTR(super.name) = "advanced";
     VATTR(offset) = 0;
     SET_DOCSTRING("Advanced io subsystem options\n\n"
		   "\toffset=bytes\t\tNumber of bytes to seek to in the image file. "
		   "Useful if there is some extra data at the start of the dd image "
		   "(e.g. partition table/other partitions)\n"
		   "\tfile=filename\t\tFilename to use for split files. If your dd image "
		   "is split across many files, specify this parameter in the order required "
		   "as many times as needed for seamless integration\n"
		   "\tA single word without an = sign represents a filename to use\n");

     VMETHOD(super.Con) = AdvIOSource_Con;
     VMETHOD(super.read_random) = AdvIOSource_read_random;
END_VIRTUAL

/** The sgzip IO Source */
static int SgzipIOSource_Destructor(void *this) {
  SgzipIOSource self = (SgzipIOSource)this;
  struct sgzip_obj *s = (struct sgzip_obj *)self->_handle;

  free(self->index);
  free(s->header);
  close(self->super.fd);
  
  return 0;
};

IOSource SgzipIOSource_Con(IOSource self, IOOptions opts) {
  SgzipIOSource this = (SgzipIOSource) self;
  struct sgzip_obj *s;
  char *offset = NULL;

  /** Get our base class to open the file: */
  if(!IOSource_Con(self, opts)) return NULL;

  /** was an offset specified? */
  offset = CALL(opts, get_value, "offset");
  if(offset)
    this->offset = parse_offsets(offset);

  s=talloc(self,struct sgzip_obj);
  this->_handle = s;
  s->header = sgzip_read_header(self->fd);
  if(!s->header) {
    talloc_free(self);
    raise_errors(EIOError, "%s is not an sgz file", self->filename);
    return NULL;
  };

  this->index=sgzip_read_index(self->fd,s);

  if(!this->index) {
    s->header=sgzip_read_header(self->fd);
    fprintf(stderr, "You may consider rebuilding the index on this file to speed things up, falling back to non-indexed method\n");
    this->index=sgzip_calculate_index_from_stream(self->fd,s);
  };

  //Set the size of this file:
  self->size = s->header->x.max_chunks * s->header->blocksize;

  talloc_set_destructor((void *)self, SgzipIOSource_Destructor);
 
  return (self);
};

int SgzipIOSource_read_random(IOSource self, char *buf, uint32_t len, uint64_t offs) {
  SgzipIOSource this = (SgzipIOSource) self;
  struct sgzip_obj *s = (struct sgzip_obj *)this->_handle;

  // add offset
  offs += this->offset;

  return sgzip_read_random(buf, len, offs, self->fd, this->index, s);
};

VIRTUAL(SgzipIOSource, IOSource)
     VATTR(super.name) = "sgzip";
     VATTR(offset) = 0;
     SET_DOCSTRING("sgzip subsystem options\n\n"
		   "\tfile=filename\t\tFilename to open\n"
		   "\toffset=bytes\t\tNumber of bytes to seek to in the "
		   "(uncompressed) image file. Useful if there is some "
		   "extra data at the start of the dd image (e.g. partition "
		   "table/other partitions)\n");

     VMETHOD(super.Con) = SgzipIOSource_Con;
     VMETHOD(super.read_random) = SgzipIOSource_read_random;
END_VIRTUAL

int EWFIOSource_Destructor(void *self) {
  EWFIOSource this = (EWFIOSource) self;

  libewf_close(this->_handle);

  return 0;
};

IOSource EWFIOSource_Con(IOSource self, IOOptions opts) {
  EWFIOSource this = (EWFIOSource)self;
  IOOptions i,j;
  LIBEWF_HANDLE *e=NULL;
  
  this->buffer = CONSTRUCT(StringIO, StringIO, Con, self);
  this->number_of_files =0;

  list_for_each_entry_safe(i,j, &(opts->list), list) {
    if(!strcmp(i->name,"offset")) {
      list_del(&i->list);
      this->offset = parse_offsets(i->value);
      if(this->offset<0) {
	talloc_free(self);
	return raise_errors(EIOError, "Invalid argument");
      };
    }
    else if(!strcmp(i->name,"filename")) {
      char *temp = talloc_strdup(self, i->value);
      list_del(&i->list);
      CALL(this->buffer, write, (char *)&temp, sizeof(temp));
      this->number_of_files++;
    };
  };
 
  if(this->number_of_files == 0) {
    talloc_free(self);
    return raise_errors(EIOError, "No files were given");
  };

  TRY {
    e = libewf_open((const char **)this->buffer->data, this->number_of_files, 
			       LIBEWF_OPEN_READ);
    this->_handle = e;
  } EXCEPT(E_ANY) {
    return raise_errors(EIOError, except_str);
  };

  if(!e) {
    talloc_free(self);
    return raise_errors(EIOError, "This does not appear to be an EWF file");
  };

  self->size = libewf_data_size(e);

  talloc_set_destructor((void *)self, EWFIOSource_Destructor);
  return self;
};

int EWFIOSource_read_random(IOSource self, char *buf, uint32_t len, uint64_t offs) {
  EWFIOSource this = (EWFIOSource) self;
  LIBEWF_HANDLE *e=(LIBEWF_HANDLE *)this->_handle;

  // add offset
  offs += this->offset;
  return libewf_read_random(e, buf, len, offs);
};

VIRTUAL(EWFIOSource, IOSource)
     VATTR(super.name) = "ewf";
     VATTR(offset) = 0;
     SET_DOCSTRING("An Expert Witness IO subsystem\n\n"
		   "\toffset=bytes\t\tNumber of bytes to seek to in the "
		   "(uncompressed) image file. Useful if there is some extra data "
		   "at the start of the dd image (e.g. partition table/other partitions\n"
		   "\tfilename=file.e0?\t\tFilename to use for split files. If your dd "
		   "image is split across many files, specify this parameter in the order "
		   "required as many times as needed for seamless integration\n"
		   "\tA single word without an = sign represents a filename to use\n");

     VMETHOD(super.Con) = EWFIOSource_Con;
     VMETHOD(super.read_random) = EWFIOSource_read_random;
END_VIRTUAL

/** This is a central dispatcher for all iosubsystems by their name: */
IOSource iosubsys_Open(char *drivername, IOOptions options) {
  IOSource driver;

  if(!strcasecmp(drivername,"standard")) {
    driver = CONSTRUCT(IOSource, IOSource, Con, NULL, options);
  } else if(!strcasecmp(drivername,"advanced")) {
    driver = (IOSource)CONSTRUCT(AdvIOSource, IOSource, super.Con, NULL, options);
  } else if(!strcasecmp(drivername,"sgzip")) {
    driver = (IOSource)CONSTRUCT(SgzipIOSource, IOSource, super.Con, NULL, options);
  } else if(!strcasecmp(drivername,"ewf")) {
    driver = (IOSource)CONSTRUCT(EWFIOSource, IOSource, super.Con, NULL, options);
  } else {
    return raise_errors(EIOError, "No such driver %s", drivername);
  };

  return driver;
};

/** Returns an option object initialised from the string s. */
IOOptions iosubsys_parse_options(char *s) {
  char *x,*y,*z;
  IOOptions result;
  char *temp;

  if(!s) return NULL;

  result =  CONSTRUCT(IOOptions, IOOptions, add, NULL, NULL, NULL, NULL);
  temp = talloc_strdup(result, s);
  z=temp;
  while(1) {
    // Find the next comma:
    y=index(z,',');
    if (y) *y='\0';
    
    //Now find the = sign
    x=index(z,'=');
    
    if(x) {
      *x='\0';
      x++;
    };
    
    CONSTRUCT(IOOptions, IOOptions, add, result, result, z,x);
    if(!y) break;
    z=y+1;
  };

  return result;
};

/* Parses the string for a number. Can interpret the following suffixed:

  k - means 1024 bytes
  M - Means 1024*1024 bytes
  S - Menas 512 bytes (sector size)
*/
int64_t parse_offsets(char *string) {
  uint64_t result=0;
  int multiplier=1;
  int offs=0;
  
  result=atoll(string);
  offs = strcspn(string,"KkMmSs");

  if(offs) {
    switch(string[offs]) {
    case 'K':
    case 'k':
      multiplier=1024;
      break;
    case 'm':
    case 'M':
      multiplier=1024*1024;
      break;
    case 'S':
    case 's':
      multiplier=512;
      break;
    };
  };

  return(multiplier*result);
};
