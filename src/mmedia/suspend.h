void suspend_memory(j_common_ptr cinfo, int row, int sector);
void resume_memory(j_common_ptr cinfo);
void *alloc_small(j_common_ptr cinfo, int pool_id, size_t sizeofobject);

struct my_memory_mgr {
  struct jpeg_memory_mgr pub;	/* public fields */

  // This is for libjpegs benefit:
  jvirt_sarray_ptr virt_sarray_list;
  jvirt_barray_ptr virt_barray_list;
  JDIMENSION last_rowsperchunk;	/* from most recent alloc_sarray/barray */

  // All memory is allocated to this pool.
  char *pool;
  char *shadow_pool;

  // A highwater mark for pool allocations
  long pool_size;

  // This is the very end of the allocated pool.
  long total_space_allocated;
  long total_space_shadowed;

  // The row number where we suspended
  int row;
  
  // The sector where we suspended
  int sector;
};

typedef struct my_memory_mgr *my_mem_ptr;


