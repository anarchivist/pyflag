/** This is the implementation of the new sgz */
#include "sgzlib.h"

void compress_block(SgzipFile self);

SgzipFile SgzipFile_OpenFile(SgzipFile self, char *filename) {
  self->io = (StringIO)CONSTRUCT(DiskStringIO, DiskStringIO, OpenFile, self, filename, O_RDONLY);

  if(!self->io) {
    raise_errors(EIOError, "Could not open file %s", filename);
    goto error;
  };

  // now parse ourselves from the file:
  self->super.Con((Packet)self, NULL);
  self->super.Read((Packet)self, self->io);

  // Is this a supported file?
  if(0 != strcmp(self->packet.magic, "sgz")) {
    raise_errors(EIOError, "File does not look like an sgz file");
    goto error;
  };

  // This should not be needed - sgzip file format needs to be big
  // endian:
  self->packet.blocksize = ntohl(self->packet.blocksize);

  // Check for sanity:
  if(self->packet.blocksize > 1024*1024) {
    raise_errors(EIOError, "Blocksize (%u) is too large - not supported.", self->packet.blocksize);
    goto error;
  };

  // This is our cache
  self->cache = talloc_size(self, self->packet.blocksize);
  self->cached_block_offs = -1;

  // Read the index from the back of the file:
  {
    char magic[6];

    CALL(self->io, seek, -6, SEEK_END);
    CALL(self->io, read, magic, 6);

    // Its not an error to not have an index, but we cant seek in the
    // file if we dont. (maybe we could build the index automatically?)
    if(0 == memcmp(magic, ZSTRING_NO_NULL("sgzidx"))) {
      uint64_t file_size = CALL(self->io, seek, 0, SEEK_END);

      // There is an index - lets read it:
      self->index_stream = CONSTRUCT(StringIO, StringIO, Con, self);
      
      // The first element of the index array must be 0
      //uint64_t x=0;
      //CALL(self->index_stream, write, (char *)&x, sizeof(x));

      // How many items?
      CALL(self->io,seek,file_size -6 - sizeof(self->max_chunks), SEEK_SET);

      //FIXME: SGZip must use big endianess on the wire
      CALL(self->io, read, (char *)&self->max_chunks, sizeof(self->max_chunks));
      //unpack(self, FORMAT_INT, self->io, (void *)&count);

      CALL(self->io, seek, file_size -6 - sizeof(self->max_chunks) 
				      - self->max_chunks * sizeof(uint64_t), SEEK_SET);
      // read the data into the index:
      CALL(self->index_stream, read_stream, self->io, self->max_chunks * sizeof(uint64_t));

      // Now we have our index (we dont need to worry about memory
      // because that will be cleaned up by talloc when we are done):
      self->index = (uint64_t *)self->index_stream->data;
    };
  };
 
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
    self->readptr = self->max_chunks * self->packet.blocksize + offset;
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
  
  while(len>0) {
    //If we no longer have any more blocks (we reached the end of the file)
    if(block_offs >= self->max_chunks-1) break;

    //Here we decide if we have a cache miss:
    if(self->cached_block_offs != block_offs) {
      //Length of this block
      int clength=self->index[block_offs+1]-self->index[block_offs];

      // Check to make sure that the compressed length is not too big
      if(clength >= (self->packet.blocksize + 1024)) {
	raise_errors(EIOError,"clength (%u) is too large (blocksize is %u)",clength,self->packet.blocksize);
	goto error;
      };

      if(clength<0) {
	raise_errors(EIOError,"clength (%u) is negative?",clength);
	goto error;
      };

      /** FIXME: This seek is a little magical - there is lots of
	  magic to go around little bugs in the file format. The SGZIP
	  file format needs to change to be more flexible. Probably
	  best to write the offset of the compressed buffer into the
	  index directly.
      */
      //Read the compressed block from the file:
      CALL(self->io, seek, self->index[block_offs], SEEK_SET);

      if(CALL(self->io, read, compressed_buffer, clength) < clength) {
	raise_errors(EIOError, "Unable to read %u bytes from file at offset %llu", 
		     clength, self->index[block_offs]);
	goto error;
      };

      length=self->packet.blocksize;
      result=uncompress(self->cache, &length, compressed_buffer, clength);
    
      //Inability to decompress the data is non-recoverable:
      if(!result==Z_OK) {
	raise_errors(EIOError, "Cant decompress block %lu \n" , block_offs);
	goto error;
      };

      //Note which block we decompressed
      self->cached_block_offs = block_offs;
      self->cached_length =length;
    } else {
      //Cache hit - data is valid
      length=self->cached_length;
    };

    //The available amount of data to read:
    available = length - buffer_offset;
    if(available>len) {
      available=len;
    };

    //Copy the right data into the buffer
    memcpy(data + copied, self->cache + buffer_offset, available);
    len-=available;
    copied+=available;
    block_offs++;
    buffer_offset=0;
  }


  // Advance our readptr:
  self->readptr += copied;

  return(copied);

 error:
  return -1;
};

/** This is the destructor */
int SgzipFile_destroy(void *this) {
  SgzipFile self = (SgzipFile)this;
  int number_of_chunks;

  // Flush the cache:
  compress_block(self);
  compress_block(self);

  number_of_chunks = ntohl(self->max_chunks);

  // Write the index:
  CALL(self->io, write, self->index_stream->data, self->index_stream->size);
  pack(FORMAT_INT, (char *)&number_of_chunks, self->io);
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
  self->cache = talloc_size(self, blocksize);
  self->index_stream = CONSTRUCT(StringIO, StringIO, Con, self);

  // Initialise the header
  self->packet.blocksize = htonl(blocksize);
  memcpy(&self->packet.magic, ZSTRING_NO_NULL("sgz"));
  memcpy(&self->packet.compression, ZSTRING_NO_NULL("gzip"));

  // Write the header on the disk:
  self->super.Write((Packet)self, self->io);

  self->packet.blocksize = blocksize;

  // Make sure that when this file is destroyed, we flush ourself to
  // the disk:
  talloc_set_destructor(self, SgzipFile_destroy);
  
  return self;

 error:
  talloc_free(self);
  return NULL;
};

void compress_block(SgzipFile self) {
  char compressed_buffer[self->packet.blocksize];
  unsigned long int clength;
  int result = compress2(compressed_buffer, &clength, self->cache, self->packet.blocksize, self->level);
  
  if(result != Z_OK) {
    DEBUG("Cant compress block of size %u into size %lu...\n" , self->packet.blocksize, clength);
  };
  
  // The buffer is written as the length into our buffer:
  // FIXME - this needs to be done in network order:
  {
    unsigned long int tmp_length = ntohl(clength);

    pack(FORMAT_INT, (char *)&tmp_length, self->io);
  };

  // Where are we? Add our position to the index - the index always
  // points at cdata
  CALL(self->index_stream, write, 
       (char *)&self->io->readptr, sizeof(self->io->readptr));

  CALL(self->io, write, compressed_buffer, clength);

  // Clear the cache:
  memset(self->cache, 0, self->packet.blocksize);
  self->cached_length = 0;

  self->max_chunks++;
};

int SgzipFile_append(SgzipFile self, char *data, int len) {
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

     VATTR(level) = 5;
     VMETHOD(OpenFile) = SgzipFile_OpenFile;
     VMETHOD(seek) = SgzipFile_seek;
     VMETHOD(read) = SgzipFile_read;
     VMETHOD(CreateFile) = SgzipFile_CreateFile;
     VMETHOD(append) = SgzipFile_append;
END_VIRTUAL
