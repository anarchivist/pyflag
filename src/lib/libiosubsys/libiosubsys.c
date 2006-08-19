#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include "list.h"
#include "misc.h"
#include "class.h"
#include "libiosubsys.h"
#include "except.h"

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
    list_next(opts, &(opts->list), list);
    if(opts) name = opts->name;
  };

  if(name) {
    self->filename = talloc_strdup(self,name);
    self->fd = open(name,O_RDONLY);

    /** We failed to open the file */
    if(self->fd<0) {
      talloc_free(self);
      return raise_errors(EIOError, "Unable to open file %s\n", name);
    };
  };

  // Find out the size of the file:
  self->size = lseek(self->fd, 0, SEEK_END);

  talloc_set_destructor(self,IOSource_Destructor);
  return self;
};

int IOSource_read_random(IOSource self, char *buf, uint32_t len, uint64_t offs) {
  lseek(self->fd, offs, SEEK_SET);

  return read(self->fd, buf, len);
};

VIRTUAL(IOSource, Object)
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
  IOOptions t;
  int last_max_length=0;

  this->number =0;
  this->buffer=CONSTRUCT(StringIO, StringIO, Con, self);

  /** Use the opts to build our internal list of offsets. This is an
      array rather than a linked list for performance reasons. 
  **/
  list_for_each_entry(t, &(opts->list), list) {
    if(!strcmp("filename",t->name)) {
      int i;

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

  // Done.
  self->size = last_max_length;
  talloc_set_destructor(self, AdvIOSource_Destructor);
  return self;
};

/** We read random data from the files: */
int AdvIOSource_read_random(IOSource self, char *buf, uint32_t len, uint64_t offs) {
  AdvIOSource this = (AdvIOSource) self;
  struct split_file *temp=(struct split_file *)this->buffer->data;
  int i,total=0;

  /** First check if the offset is too much: */
  if(offs>self->size) return 0;

  /** We need to work out which file it is - this could be a binary
      search but for now its linear. 
  */
  for(i=0; i<this->number && len>0; i++) {
    if(temp[i].start_offset <= offs && offs < temp[i].end_offset) {
      // The number of bytes available within this chunk
      int available = temp[i].end_offset-offs;
      // The amount of data to read - len is how much is required.:
      int length = min(available,len);

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
  free(self->index);
  free(self->sgzip.header);
  close(self->super.fd);
  
  return 0;
};

IOSource SgzipIOSource_Con(IOSource self, IOOptions opts) {
  SgzipIOSource this = (SgzipIOSource) self;

  /** Get our base class to open the file: */
  if(!IOSource_Con(self, opts)) return NULL;

  this->sgzip.header = sgzip_read_header(self->fd);
  if(!this->sgzip.header) {
    talloc_free(self);
    return raise_errors(EIOError, "%s is not an sgz file", self->filename);
  };

  this->index=sgzip_read_index(self->fd,&(this->sgzip));

  if(!this->index) {
    this->sgzip.header=sgzip_read_header(self->fd);
    fprintf(stderr, "You may consider rebuilding the index on this file to speed things up, falling back to non-indexed method\n");
    this->index=sgzip_calculate_index_from_stream(self->fd,&(this->sgzip));
  };

  //Set the size of this file:
  self->size = this->sgzip.header->x.max_chunks * this->sgzip.header->blocksize;

  talloc_set_destructor(self, SgzipIOSource_Destructor);
  return self;
};

int SgzipIOSource_read_random(IOSource self, char *buf, uint32_t len, uint64_t offs) {
  SgzipIOSource this = (SgzipIOSource) self;

  return sgzip_read_random(buf, len, offs, self->fd, this->index, &(this->sgzip));
};

VIRTUAL(SgzipIOSource, IOSource)
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

  libewf_close(this->handle);

  return 0;
};

IOSource EWFIOSource_Con(IOSource self, IOOptions opts) {
  EWFIOSource this = (EWFIOSource)self;
  IOOptions i;
  
  this->buffer = CONSTRUCT(StringIO, StringIO, Con, self);
  this->number_of_files =0;

  list_for_each_entry(i, &(opts->list), list) {
    if(!strcmp(i->name,"filename")) {
      char *temp = talloc_strdup(self, i->value);
      CALL(this->buffer, write, (char *)&temp, sizeof(temp));
      this->number_of_files++;
    };
  };
 
  if(this->number_of_files == 0) {
    talloc_free(self);
    return raise_errors(EIOError, "No files were given");
  };

  TRY {
    this->handle = libewf_open((const char **)this->buffer->data, this->number_of_files, 
			       LIBEWF_OPEN_READ);
  } EXCEPT(E_ANY) {
    return raise_errors(EIOError, except_str);
  };

  if(!this->handle) {
    talloc_free(self);
    return raise_errors(EIOError, "This does not appear to be an EWF file");
  };

  self->size = libewf_data_size(this->handle);

  talloc_set_destructor(self, EWFIOSource_Destructor);
  return self;
};

int EWFIOSource_read_random(IOSource self, char *buf, uint32_t len, uint64_t offs) {
  EWFIOSource this = (EWFIOSource) self;

  return libewf_read_random(this->handle, buf, len, offs);
};

VIRTUAL(EWFIOSource, IOSource)
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
