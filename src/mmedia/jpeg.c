/*** This is the python binding for the jpeg_decoder object */
#include <Python.h>
#include "jpeglib.h"
#include <setjmp.h>
#include "talloc.h"
#include <stdio.h>
#include <fcntl.h>
#include <jerror.h>

#define SECTOR_SIZE 512
static char empty[128];

//#define DEBUG

/** We need to do some special error handling because we expect lots
    of errors from the discriminator 
*/
struct my_error_mgr {
  struct jpeg_error_mgr pub;    /* "public" fields */

  jmp_buf setjmp_buffer;        /* for return to caller */
};

typedef struct my_error_mgr * my_error_ptr;

// A constant end marker that can be artificially inserted when needed
static const char *end_marker = "\xFF\xD9";

// We use a memory buffered source manager:
struct my_src_mgr {
  struct jpeg_source_mgr pub;
  int offset;
  int length;

  PyObject *fd;
  PyObject *sector;

  // These are used to keep track of approximate sectors which yield
  // no errors
  int last_good_row;
  int last_good_sector;
  int prelast_good_sector;

  // Which sector we are currently reading
  int current_sector;

  // Artificially truncate the file at this sector
  int maximum_sector;

  // A tally of errors that we consider are noteworthy
  int error_count;

  // The end of the image in sector
  int last_sector;
};

/*
 
Error handling
--------------
The discriminator will be encountering a large number of errors, some
of which we wish to ignore, others we wish to add to our error tally.

We use our own error manager which allows us to eliminate the the
printing out of error messages, as well as have fine control over
which errors count more than others.

 */
METHODDEF(void)
  my_error_exit (j_common_ptr cinfo)
{
  my_error_ptr myerr = (my_error_ptr) cinfo->err;

  /* Return control to the setjmp point */
  longjmp(myerr->setjmp_buffer, 1);
}

void (*jpeg_output_message)(j_decompress_ptr cinfo);

METHODDEF(void)
  my_output_message(j_decompress_ptr cinfo) {
  // Do nothing - we dont really want to print all that crap to the terminal.
  struct my_src_mgr *self = (struct my_src_mgr *)cinfo->src;

  if(self->maximum_sector && 
     self->current_sector >= self->maximum_sector) {
    
    switch(cinfo->err->msg_code) {
      // This occurs when we got a marker we did not expect.
    case JWRN_HIT_MARKER:
      break;

      // This occurs when we have too much data before the marker
      // (FIXME - this is not really reliable enogh should we just
      // forget it?)
    case JWRN_EXTRANEOUS_DATA:
      self->last_good_sector = self->current_sector - 2;
      self->error_count ++;  
      break;

    default:
      self->error_count ++;
    };
  } else {
    self->error_count ++;
  };

#ifdef DEBUG
  jpeg_output_message(cinfo);
#endif

};

/*
 Source Manager
----------------

The source manager allows us to have control over the state of the
decoding. We feed the decode a sector at a time and are then able to
watch the error count increase with each sector fed. This allows us to
determine with greater accuracy which sector causes corruption.

*/
static void my_init_source (j_decompress_ptr cinfo) {
  struct my_src_mgr *self = (struct my_src_mgr *)cinfo->src;
  self->sector = NULL;
};

static int my_fill_input_buffer (j_decompress_ptr cinfo) {
  struct my_src_mgr *self = (struct my_src_mgr *)cinfo->src;
  
  // Where are we in the input file: FIXME - should we just keep track
  // of this ourselves?
  {
    PyObject *result = PyObject_CallMethod(self->fd, "tell", NULL);
    if(result) {
      self->current_sector = PyLong_AsLong(result)/SECTOR_SIZE;
    };
    Py_DECREF(result);
  };

  /* 
     Are there any errors we dont know about? Adjust our record of the
     best sectors. The idea is that last_good_sector is guaranteed to
     have correct data upto it. The discontinuity is expected to occur
     a small number of sectors after that.
  */
  if(0==self->error_count && self->last_good_row != cinfo->output_scanline) {
    self->prelast_good_sector = self->last_good_sector;
    self->last_good_row = cinfo->output_scanline;
    self->last_good_sector = self->current_sector;
  };

#ifdef DEBUG
  if(cinfo->err->num_warnings) {
    printf("Errors found in sector %u\n", self->prelast_good_sector);
  };

  printf("We were asked to get more data here. Scan line %u Last good sector (%u) Errors %u...\n", 
	 cinfo->output_scanline, self->last_good_sector, cinfo->err->num_warnings);
#endif

  /*
    If we were told to stop reading here, we append an end
    marker. This is needed to cause the decompressor to flush the
    current rows. We are then able to get partial rows.
  */
  if(self->maximum_sector && self->current_sector >= self->maximum_sector) {
    self->pub.next_input_byte = (unsigned char *)end_marker;
    self->pub.bytes_in_buffer = 2;

  } else {
    // Read a new sector:
    if(self->sector) {
      Py_DECREF(self->sector);
    };
    
    self->sector = PyObject_CallMethod(self->fd, "read", "(i)", SECTOR_SIZE);
    if(!self->sector) return FALSE;
  
    // Provide this sector to the decompressor:
    PyString_AsStringAndSize(self->sector, 
			     (char **)&self->pub.next_input_byte, 
			     (int *)&self->pub.bytes_in_buffer);
  };

  return TRUE;
};

/** This is called when the decompressor wants to skip some data */
static void my_skip_input_data (j_decompress_ptr cinfo, long num_bytes) {
  struct my_src_mgr *self = (struct my_src_mgr *) cinfo->src;
  PyObject *tmp;
  int buffer_length =  self->pub.bytes_in_buffer;

  // We try to satisfy the skip from within our currenct sector
  buffer_length -= num_bytes;
  self->pub.next_input_byte += num_bytes;

  // If we cant - we read more data from the source:
  if(buffer_length < 0 ) {
    tmp = PyObject_CallMethod(self->fd, "read", "(i)", -buffer_length);
    if(tmp) {
      Py_DECREF(tmp);
    };

    buffer_length = 0;
  };

  self->pub.bytes_in_buffer = buffer_length;

#ifdef DEBUG
  printf("Skipping %u bytes\n", num_bytes);
#endif
  return;
};

// Noop
static void my_term_source (j_decompress_ptr cinfo) {  
};

/* Note that we only borrow a reference to the input buffer so we dont
 need to copy it all the time - it is the responsibility of the caller
 to ensure that the memory will continue to be available for the life
 of this source. Typically we just need to incref it. */
static void jpeg_my_src(j_decompress_ptr cinfo, PyObject *fd) {
  struct my_src_mgr *self;

  self = talloc_zero(cinfo, struct my_src_mgr);
  cinfo->src = (struct jpeg_source_mgr *)self;

  self->fd = fd;

  self->pub.init_source = my_init_source;
  self->pub.fill_input_buffer = my_fill_input_buffer;
  self->pub.skip_input_data = my_skip_input_data;
  self->pub.resync_to_restart = jpeg_resync_to_restart; /* use default method */
  self->pub.term_source = my_term_source;

  // We do not populate the buffer first off - the decompressor will
  // call my_fill_input_buffer immediately
  self->pub.bytes_in_buffer = 0;
  self->pub.next_input_byte = NULL;
};

typedef struct {
  PyObject_HEAD

  // This is the python file like object we use to read from:
  PyObject *fd;

  // The output buffer where we decode the image to
  unsigned char *frame;

  // The decompressor object itself (This is also the main talloc context):
  j_decompress_ptr cinfo;

  // Some stats about this image:
  int row_stride;
  // A cache of integrals
  int *integrals;
} decoder;

static void decoder_dealloc(decoder *self) {
  if(self->cinfo)
    talloc_free(self->cinfo);

  if(self->fd) {
    Py_DECREF(self->fd);
  };

  self->ob_type->tp_free((PyObject*)self);
}

static int decoder_init(decoder *self, PyObject *args) {
  if(!PyArg_ParseTuple(args, "O", &self->fd))
    return -1;

  self->integrals = NULL;
  self->cinfo = talloc(NULL, struct jpeg_decompress_struct);
  self->cinfo->err = (struct jpeg_error_mgr *)talloc(self->cinfo, struct my_error_mgr);
  jpeg_std_error(self->cinfo->err);
  
  self->cinfo->err->error_exit = my_error_exit;
  jpeg_output_message = self->cinfo->err->output_message;
  self->cinfo->err->output_message = my_output_message;

  // Hold onto the provided fd
  Py_INCREF(self->fd);

  // The decoded frame
  self->frame = NULL;


  return 0;
}

// prototypes
int estimate_row(decoder *self, int row, int left, int right);

static PyObject *decoder_decode(decoder *self, PyObject *args) {
  PyObject *result;
  JSAMPROW row_pointer[1];
  int maximum_sector=0;
  struct my_src_mgr *src;
  int start_pixel=0;
  int width;
  struct my_memory_mgr *self = (struct my_memory_mgr *)(cinfo->mem);

  if(!PyArg_ParseTuple(args, "|ii", &maximum_sector, &start_pixel)) return NULL;

  

  // Seek to the start of the stream:
  result = PyObject_CallMethod(self->fd, "seek", "(k)", 0);
  if(!result)
    return NULL;

  Py_DECREF(result);

  // Prepare ourselves for fatal errors. On errors our error manager
  // will jump back here.
  if (setjmp(((struct my_error_mgr *)self->cinfo->err)->setjmp_buffer)) {
    // Signal an error - stop decoding.
    goto abort;
  }

  // Build a new decompressor object:
  jpeg_create_decompress(self->cinfo);
  jpeg_my_src(self->cinfo, self->fd);
  
  src = (struct my_src_mgr *)self->cinfo->src;

  // Decode the data:
  jpeg_read_header(self->cinfo, TRUE);
  jpeg_start_decompress(self->cinfo);

  self->row_stride = self->cinfo->output_width * self->cinfo->output_components;
  {
    int size = sizeof(int) * self->cinfo->output_height;

    if(!self->integrals) {
      self->integrals = talloc_size(self->cinfo, size);
    };
      memset(self->integrals, 0, size);
  
    // Set some defaults:
    if(maximum_sector)
      src->maximum_sector = maximum_sector;
  };

  // Make sure we have enough space:
  {
    int buffer_size = self->row_stride * self->cinfo->output_height;
    self->frame = talloc_realloc(self->cinfo, self->frame, unsigned char, buffer_size);
    
    memset(self->frame, 0x80, buffer_size);
  };

  while (self->cinfo->output_scanline < self->cinfo->output_height) {
    int estimate;

    // Calculate where this line needs to go.
    row_pointer[0] = (unsigned char *)self->frame + 
      self->cinfo->output_scanline * self->row_stride;
    
    // Read one line at the time
    jpeg_read_scanlines(self->cinfo, row_pointer, 1);
    width=self->cinfo->output_width;
    
    // Estimate how good is this line - we try to estimate the
    // integral as we go to detect discontinuities asap:
    if(self->cinfo->output_scanline > 10 ) {
      unsigned char *j;

      // Try to see if this row is partially empty:
      for(j=row_pointer[0]; 
	  j<row_pointer[0] + self->row_stride - sizeof(empty); 
	  j+=self->cinfo->output_components) {
	if(!memcmp(empty, j, sizeof(empty))) {
	  width = (j-row_pointer[0])/self->cinfo->output_components;
	  break;
	};
      };

      if(width) {
	int row = self->cinfo->output_scanline -3;
	estimate = estimate_row(self, row,
				start_pixel, width);
#if 0
	  printf("Row %u from %u-%u - integral %u\n", self->cinfo->output_scanline, 
		 start_pixel, width,
		 estimate);
#endif

	if(estimate > 100) {
	  // Register this as an error:
	  src->error_count++;
	};
      } else break;
    };
  };

  {
    struct my_src_mgr *this = (struct my_src_mgr *) self->cinfo->src;

#ifdef DEBUG
    printf("Finished decompressing at sector %u (Errors %u)\n", this->current_sector, self->cinfo->err->num_warnings);
#endif

    if(this->error_count == 0) 
      this->last_sector = this->current_sector;
  };

  jpeg_finish_decompress(self->cinfo);

  //  return Py_BuildValue("i", width);
  Py_RETURN_NONE;

 abort:
  jpeg_abort_decompress(self->cinfo);
  jpeg_destroy_decompress(self->cinfo);
  //return Py_BuildValue("i", width);
  Py_RETURN_NONE;
};

static PyObject *py_find_frame_bounds(decoder *self, PyObject *args) {
  uint32_t i,j;
  int frame_size = self->cinfo->output_height * self->row_stride;
  int x1=0,y1=0;

  j = 0;
  for(i=0; i<frame_size; i+= sizeof(uint32_t)) {
    if( *(uint32_t *)(self->frame + i) == 0x80808080) {
      if(j==0) j = i;
    } else j=0;
    
    // We looked far enough - we have 2 full scan lines of 0x808080
    if(j && i > j + self->row_stride *2) break;
  };

  // Avoid an FPE
  if(self->row_stride) {
    y1 = i/self->row_stride - 7;
    x1 = (i % self->row_stride) / self->cinfo->output_components;
  };

  return Py_BuildValue("(ii)", x1, y1);
};

/** Calculates the integral on self->frame, between left and right
    between row and row-1. Note that left,right and row are given in
    pixels. 
*/
static int calculate_integral(decoder *self, int row, int left, int right) {
  int result=0;
  int i;

  if(self->integrals[row] && left==0 && right==self->cinfo->output_width) {
    return self->integrals[row];
  };

  for(i= left * self->cinfo->output_components;
      i < right * self->cinfo->output_components; i++) {
    unsigned char up = self->frame[(row) * self->row_stride + i];
    unsigned char down = self->frame[(row+1) * self->row_stride + i];

    result += abs(up - down);
  };

  // Try to normalise the result wrt the width calculated
  //result = result / (right - left);
  //  printf("Integral on row %u (%u-%u) is %u\n", row, left, right, result);
  self->integrals[row] = result;
  return result;
};

// Here we calculate a measure of how different this row is from the
// previous row and the next row. If the current sector does not
// belong, we expect to get a lot of noise - i.e. it will not fit well
// with the integral derived from the previous row and the next row.
int estimate_row(decoder *self, int row, int left, int right) {
  int previous_value = calculate_integral(self, row-1, left, right);
  int value = calculate_integral(self, row, left, right);
  int next_value = calculate_integral(self, row+1, left, right);
  int expected_value = abs(previous_value + next_value)/2;

  // Result scaled to 100 - 100 means the integral for this value is
  // exactly the average of the previous and next row
  //return value * 10000 / expected_value / scale;
  return abs(100 + value - expected_value)*100/(expected_value + 100);
};

/** This function uses edge detection to estimate a discontinuity
    after the provided scan line 
*/
static PyObject *py_find_discontinuity(decoder *self, PyObject *args) {
  unsigned int max_estimate = 0;
  unsigned int max_row = 0;
  int i,j;
  unsigned int min_row = 0;

  if(!PyArg_ParseTuple(args, "|i", &min_row)) return NULL;
    
  for(i=min_row; i < self->cinfo->output_height; i++) {
    unsigned int estimate;

    // Try to see if this row is partially empty:
    for(j=0; j<self->row_stride; j+=self->cinfo->output_components) {
      if(!memcmp(empty, self->frame + self->row_stride * (i+1) + j, sizeof(empty))) {
	printf("Exiting at row %u\n", i+1);
	goto exit;
      };
    };

    estimate = estimate_row(self, i, 0, self->cinfo->output_width);
    //    printf("%u - %u\n", i, estimate);

    if(estimate > max_estimate) {
      max_estimate = estimate;
      max_row = i;
    };
  };
  
 exit:
  return Py_BuildValue("(ll)", max_row, max_estimate);
};

/** Save a copy of the decoded frame as a pnm bitmap file */
static PyObject *py_save(decoder *self, PyObject *args) {
  PyObject *fd=NULL;
  char buf[1024];
  int len;
  PyObject *result;

  if(!PyArg_ParseTuple(args, "O", &fd)) return  NULL;

  if(self->row_stride) {
    len = snprintf(buf, 1023, "P6\n%u %u\n255\n", 
		   self->cinfo->output_width, 
		   self->cinfo->output_height);
    
    // Write the result onto the provided fd:
    result = PyObject_CallMethod(fd, "write", "(s#)", buf, len);
    if(!result) return NULL;
    Py_DECREF(result);
    
    result = PyObject_CallMethod(fd, "write", "(s#)", self->frame, 
				 self->cinfo->output_height * self->row_stride);
    if(!result) return NULL;
    Py_DECREF(result);
  };

  Py_RETURN_NONE;
};

static PyObject *py_warnings(decoder *self, PyObject *args) {
  struct my_src_mgr *src = (struct my_src_mgr *)self->cinfo->src;
  return Py_BuildValue("i", src->error_count);
};

static PyObject *last_good_sector(decoder *self, PyObject *args) {
  struct my_src_mgr *src = (struct my_src_mgr *)self->cinfo->src;
  return Py_BuildValue("i", src->prelast_good_sector);
};

static PyObject *last_good_row(decoder *self, PyObject *args) {
  struct my_src_mgr *src = (struct my_src_mgr *)self->cinfo->src;
  return Py_BuildValue("i", src->last_good_row);
};

static PyObject *last_sector(decoder *self, PyObject *args) {
  struct my_src_mgr *src = (struct my_src_mgr *)self->cinfo->src;
  return Py_BuildValue("i", src->last_sector);
};

static PyMethodDef decoder_methods[] = {
  {"find_frame_bounds", (PyCFunction)py_find_frame_bounds, METH_VARARGS,
   "Calculates the position of the frames end" },
  {"decode", (PyCFunction)decoder_decode, METH_VARARGS,
   "Decodes the fd"},
  {"find_discontinuity", (PyCFunction)py_find_discontinuity, METH_VARARGS,
   "Estimates the localtion of the discontinuity within the decoded "
   "frame. Takes the lengh the frame to test in bytes."},
  {"save", (PyCFunction)py_save, METH_VARARGS,
   "Save the decoded frame onto the fd given"},
  {"warnings", (PyCFunction)py_warnings, METH_VARARGS,
   "Returns the number of warnings in the latest decode"},
  {"last_good_sector", (PyCFunction)last_good_sector, METH_VARARGS,
   "Returns the last good sector as calculated by decode"},
  {"last_sector", (PyCFunction)last_sector, METH_VARARGS,
   "Returns the last sector as calculated by decode"},
  {"last_good_row", (PyCFunction)last_good_row, METH_VARARGS,
   "Returns the last good row as calculated by decode"},
  {NULL}  /* Sentinel */
};

static PyTypeObject decoderType = {
  PyObject_HEAD_INIT(NULL)
  0,                         /* ob_size */
  "jpeg.decoder",             /* tp_name */
  sizeof(decoder),        /* tp_basicsize */
  0,                         /* tp_itemsize */
  (destructor)decoder_dealloc, /* tp_dealloc */
  0,                         /* tp_print */
  0,                         /* tp_getattr */
  0,                         /* tp_setattr */
  0,                         /* tp_compare */
  0,                         /* tp_repr */
  0,                         /* tp_as_number */
  0,                         /* tp_as_sequence */
  0,                         /* tp_as_mapping */
  0,                         /* tp_hash */
  0,                         /* tp_call */
  0,                         /* tp_str */
  0,                         /* tp_getattro */
  0,                         /* tp_setattro */
  0,                         /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT,        /* tp_flags */
  "Jpeg decoder",            /* tp_doc */
  0,                         /* tp_traverse */
  0,                         /* tp_clear */
  0,                         /* tp_richcompare */
  0,                         /* tp_weaklistoffset */
  0,                         /* tp_iter */
  0,                         /* tp_iternext */
  decoder_methods,        /* tp_methods */
  0,                         /* tp_members */
  0,                         /* tp_getset */
  0,                         /* tp_base */
  0,                         /* tp_dict */
  0,                         /* tp_descr_get */
  0,                         /* tp_descr_set */
  0,                         /* tp_dictoffset */
  (initproc)decoder_init, /* tp_init */
  0,                         /* tp_alloc */
  0,                         /* tp_new */
};

static PyMethodDef JpegMethods[] = {
  {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initjpeg(void) {

  PyObject *m;

  memset(empty, 0x80, sizeof(empty));

  m = Py_InitModule("jpeg", JpegMethods);

  decoderType.tp_new = PyType_GenericNew;
  if (PyType_Ready(&decoderType) < 0)
    return;

  Py_INCREF(&decoderType);
  PyModule_AddObject(m, "decoder", (PyObject *)&decoderType);
};
