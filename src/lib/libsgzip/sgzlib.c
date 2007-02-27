/** This is the implementation of the new sgz */
#include "sgzlib.h"

void compress_block(SgzipFile self);

// 64 bit versions of this:
#if __BYTE_ORDER == __LITTLE_ENDIAN
inline uint64_t ntohll(uint64_t x) {
  uint64_t result = ((uint64_t)ntohl((uint32_t)x)) << 32 | ntohl((uint32_t)(x>>32));

  return result;
};

inline uint64_t htonll(uint64_t x) {
  return ntohll(x);
};
#else
inline uint64_t htonll(uint64_t x) {
  return x;
};

inline uint64_t ntohll(uint64_t x) {
  return x;
};
#endif

SgzipFile SgzipFile_OpenFile(SgzipFile self, char *filename) {
  self->io = (StringIO)CONSTRUCT(DiskStringIO, DiskStringIO, OpenFile, self, filename, O_RDONLY);

  if(!self->io) {
    raise_errors(EIOError, "Could not open file %s\n", filename);
    goto error;
  };

  // now parse ourselves from the file:
  self->super.Con((Packet)self, NULL);
  self->super.Read((Packet)self, self->io);

  // Is this a supported file?
  if(0 != strncmp(self->packet.magic, ZSTRING_NO_NULL("sgz"))) {
    raise_errors(EIOError, "File does not look like an sgz file\n");
    goto error;
  };

  // Check for sanity:
  if(self->packet.version != 2) {
    raise_errors(EIOError, "The version of sgzip in this file is not supported.\n");
    goto error;
  };

  if(self->packet.blocksize > 1024*1024) {
    raise_errors(EIOError, "Blocksize (%u) is too large - not supported.\n", self->packet.blocksize);
    goto error;
  };

  // This is our cache - with a little fat
  self->cache = talloc_size(self, self->packet.blocksize+100);
  self->cached_block_offs = -1;

  // Read the index from the back of the file:
  {
    // Its not an error to not have an index, but we cant seek in the
    // file if we dont. (maybe we could build the index automatically?)
    uint64_t file_size = CALL(self->io, seek, 0, SEEK_END);
    int i;
    char magic[6];
    
    // Position ourself to read all the data we need:
    file_size -= 6 + sizeof(uint64_t) * 2;
    CALL(self->io, seek, file_size , SEEK_SET);
    
    // The maximum number of chunks
    unpack(self, FORMAT_INT, self->io, (void *)&self->max_chunks);

    // The total file size:
    CALL(self->io, read, (char *)&self->size, sizeof(uint64_t));
    self->size = ntohll(self->size);
    
    // The index magic:
    CALL(self->io, read, magic, 6);
    
    // Sanity checking:
    if(0 != memcmp(magic, ZSTRING_NO_NULL("sgzidx"))) {
      DEBUG("No index found - is file truncated?\n");
      goto no_index;
    };
    
    // Index size is bigger than file size:
    if(self->max_chunks * sizeof(uint64_t) > self->io->readptr) {
      raise_errors(EIOError,"Index seems to be corrupt?\n");
      goto no_index;
    };

    // File size is incorrect - it needs to be somewhere in the last chunk:
    if(abs(self->size - (self->max_chunks-1) * self->packet.blocksize) > self->packet.blocksize) {
      DEBUG("It appears that the size of this file (%llu) is incorrect"
	    "- will pad to next blocksize\n", self->size);

      self->size = self->max_chunks * self->packet.blocksize;
    };

    // Now rewind to the start of the index:
    CALL(self->io, seek, file_size - self->max_chunks * sizeof(uint64_t), SEEK_SET);
  
    // read the data into the index:
    self->index_stream = CONSTRUCT(StringIO, StringIO, Con, self);
    CALL(self->index_stream, read_stream, self->io, (self->max_chunks + 1) * sizeof(uint64_t));
    
    // Now we have our index (we dont need to worry about memory
    // because that will be cleaned up by talloc when we are done):
    self->index = (uint64_t *)self->index_stream->data;

    // Convert the index from network order:
    for(i=0;i<self->max_chunks + 1;i++)
      self->index[i]=ntohll(self->index[i]);
  };
 
  return self;

  // If we have no index, we need to seek back after the header and
  // hopefully start reading from there.
 no_index:
  CALL(self->io, seek, sizeof(self->packet), SEEK_SET);
  return self;

 error:
    talloc_free(self);
    return NULL;
}

int SgzipFile_seek(SgzipFile self, off_t offset, int whence) {
  switch(whence) {
    // Set the readptr:
  case SEEK_SET:
    self->readptr = offset;
    break;
  case SEEK_CUR:
    self->readptr += offset;
    break;
  case SEEK_END:
    self->readptr = self->size + offset;
    break;
  default:
    DEBUG("unknown whence");
  };

  return self->readptr;
};

int SgzipFile_read(SgzipFile self, char *data, int len) {
  // The block we need to start with
  int block_offs = (int)(self->readptr / self->packet.blocksize);

  // The offset within the block where we start reading
  int buffer_offset = self->readptr % self->packet.blocksize;

  // A little extra fat - this is where we put the compressed data -
  // decompressed data goes right in the cache
  char compressed_buffer[self->packet.blocksize + 1024];
  unsigned long int length=0, copied=0, result=0, available=0;

  // clamp the read to the file size:
  if(self->readptr + len > self->size) 
    len = self->size - self->readptr;
  
  while(len>0) {
    //Here we decide if we have a cache miss:
    if(self->cached_block_offs != block_offs) {
      //Length of the compressed block
      unsigned int clength;

      // Read the length from the file - only if we have an
      // index. otherwise we just hope and pray.
      if(self->index) {
	if(CALL(self->io, seek, self->index[block_offs], SEEK_SET)!=self->index[block_offs]) {
	  raise_errors(EIOError, "Unable to seek to required point %llu in file. "
		       "Maybe the index is corrupted?\n", self->index[block_offs]);
	  goto error;
	};
      };

      unpack(self, FORMAT_INT, self->io, (void *)&clength);

      if(clength > self->packet.blocksize + 1024) {
	raise_errors(EIOError, "Block length too large at %u\n", clength);
	length = self->packet.blocksize;
	goto null_fill;
      };

      //Read the compressed block from the file:
      if(CALL(self->io, read, compressed_buffer, clength) < clength) {
	if(self->index)
	  raise_errors(EIOError, "Unable to read %u bytes from file at offset %llu\n", 
		       clength, self->index[block_offs]);
	length = self->packet.blocksize;
	goto null_fill;
      };

      length=self->packet.blocksize;
      result=uncompress((unsigned char *)self->cache, &length, 
			(unsigned char *)compressed_buffer, clength);
    
      //Inability to decompress the data is non-recoverable:
      if(!result==Z_OK) {
	raise_errors(EIOError, "Cant decompress block %lu \n" , block_offs);
	length = self->packet.blocksize;
	goto null_fill;
      };
      
    null_fill:
      //Note which block we decompressed
      self->cached_block_offs = block_offs;
      self->cached_length =length;
    } else {
      //Cache hit - data is valid
      length=self->cached_length;
    };

    //The available amount of data to read:
    available = length - buffer_offset;
    // No data is available to be read - quit
    if(!available) 
	break;
    if(available>len) {
      available=len;
    };

    //Copy the right data into the buffer
    memcpy(data + copied, self->cache + buffer_offset, available);
    len-=available;
    copied+=available;
    block_offs++;
    buffer_offset=0;

    // Advance our readptr:
    self->readptr += available;
  }

  return(copied);

 error:
  return -1;
};

/** This is the destructor */
int SgzipFile_destroy(void *this) {
  SgzipFile self = (SgzipFile)this;
  int i;

  // Flush the cache:
  compress_block(self);
  compress_block(self);

  // First we need to convert the index to network order for writing:
  for(i=0; i<self->max_chunks + 1; i++) 
    self->index[i] = htonll(self->index[i]);

  // Write the index:
  CALL(self->io, write, self->index_stream->data, self->index_stream->size);
  pack(FORMAT_INT, (char *)&self->max_chunks, self->io);

  // write the file size:
  self->size = htonll(self->size);
  CALL(self->io, write, 
       (char *)&self->size, sizeof(self->size));

  CALL(self->io, write, ZSTRING_NO_NULL("sgzidx"));

  // Flush the file out.
  talloc_free(self->io);

  //Close the fd:
  close(self->fd);

  return 1;
};

/** We create a file for writing: */
SgzipFile SgzipFile_CreateFile(SgzipFile self, int fd, int blocksize) {
  CachedWriter writer = CONSTRUCT(CachedWriter, CachedWriter, Con, self, NULL);
  if(!writer) goto error;

  // Call our base class:
  self->super.Con((Packet)self, NULL);

  // Set an fd so we just stream to it 
  writer->fd = fd;
  self->io = (StringIO)writer;

  // For writing we use a CachedWriter:
  self->cache = talloc_size(self, blocksize+100);
  self->index_stream = CONSTRUCT(StringIO, StringIO, Con, self);
  self->index = (uint64_t *)self->index_stream->data;

  // Initialise the header
  self->packet.blocksize = blocksize;
  memcpy(&self->packet.magic, ZSTRING_NO_NULL("sgz"));
  memcpy(&self->packet.compression, ZSTRING_NO_NULL("gzip"));

  // Write the header on the disk:
  self->super.Write((Packet)self, self->io);

  self->packet.blocksize = blocksize;

  // Make sure that when this file is destroyed, we flush ourself to
  // the disk:
  talloc_set_destructor((void *)self, SgzipFile_destroy);
  
  return self;

 error:
  talloc_free(self);
  return NULL;
};

void compress_block(SgzipFile self) {
  unsigned long int clength=compressBound(self->packet.blocksize);
  char compressed_buffer[clength];
  int result;

  result = compress2((unsigned char *)compressed_buffer, &clength, 
		     (unsigned char *)self->cache, 
		     self->packet.blocksize, 
		     self->level);  
  if(result != Z_OK) {
    DEBUG("Cant compress block of size %u into size %lu...\n" , 
	  self->packet.blocksize, clength);
  };
  
  // Where are we? Add our position to the index - the index always
  // points at the cdata length
  CALL(self->index_stream, write, 
       (char *)&self->io->readptr, sizeof(self->io->readptr));

  // The compressed buffer is written as length, data:
  pack(FORMAT_INT, (char *)&clength, self->io);

  // Now write the compressed buffer
  CALL(self->io, write, compressed_buffer, clength);

  // Clear the cache:
  memset(self->cache, 0, self->packet.blocksize);
  self->cached_length = 0;

  self->max_chunks++;
};

int SgzipFile_append(SgzipFile self, char *data, int len) {
  self->size += len;

  while(len > 0 ) {
    // The available space in the cache:
    int available = self->packet.blocksize - self->cached_length;
    int to_write = min(len, available);

    // Append as much data as possible to the cache:
    memcpy(self->cache + self->cached_length, data, to_write);

    len -= to_write;
    self->cached_length += to_write;

    // Is the cache full? If so flush it:
    if(self->cached_length == self->packet.blocksize) {
      compress_block(self);
    };
  };

  return 1;
};

VIRTUAL(SgzipFile, Packet)
     INIT_STRUCT(packet, SGZIP_FORMAT);

// This is sgzip version 2 format - not compatible with older version.
     VATTR(packet.version) = 2;
     VATTR(level) = 5;
     VMETHOD(OpenFile) = SgzipFile_OpenFile;
     VMETHOD(seek) = SgzipFile_seek;
     VMETHOD(read) = SgzipFile_read;
     VMETHOD(CreateFile) = SgzipFile_CreateFile;
     VMETHOD(append) = SgzipFile_append;
END_VIRTUAL
