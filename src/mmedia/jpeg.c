/*** This is the python binding for the jpeg_decoder object */
#include <Python.h>
#include "jpeglib.h"
#include <setjmp.h>
#include "talloc.h"

/** We need to do some special error handling because we expect lots
    of errors from the discriminator 
*/
struct my_error_mgr {
  struct jpeg_error_mgr pub;    /* "public" fields */

  jmp_buf setjmp_buffer;        /* for return to caller */
};

typedef struct my_error_mgr * my_error_ptr;

/*
 * Here's the routine that will replace the standard error_exit method:
 */
METHODDEF(void)
  my_error_exit (j_common_ptr cinfo)
{
  my_error_ptr myerr = (my_error_ptr) cinfo->err;

  /* Return control to the setjmp point */
  longjmp(myerr->setjmp_buffer, 1);
}

METHODDEF(void)
  my_output_message(j_common_ptr cinfo) {
  // Do nothing - we dont really want to print all that crap to the terminal.
};

// We use a memory buffered source manager:
struct my_src_mgr {
  struct jpeg_source_mgr pub;
  unsigned char *input;
  int offset;
  int length;
};

static void my_init_source (j_decompress_ptr cinfo) {
};

static int my_fill_input_buffer (j_decompress_ptr cinfo) {
  // We cant get more data - if its needed its an error:
  return FALSE;
};

static void my_skip_input_data (j_decompress_ptr cinfo, long num_bytes) {
  struct my_src_mgr *self = (struct my_src_mgr *) cinfo->src;

  self->pub.next_input_byte += num_bytes;
  self->pub.bytes_in_buffer -= num_bytes;
  return;
};

static void my_term_source (j_decompress_ptr cinfo) {  
};

/* Note that we only borrow a reference to the input buffer so we dont
 need to copy it all the time - it is the responsibility of the caller
 to ensure that the memory will continue to be available for the life
 of this source. Typically we just need to incref it. */
static void jpeg_my_src(j_decompress_ptr cinfo, unsigned char *buff, int length) {
  struct my_src_mgr *self;

  self = talloc(cinfo, struct my_src_mgr);
  cinfo->src = (struct jpeg_source_mgr *)self;

  
  self->input = buff;
  self->length = length;

  self->pub.init_source = my_init_source;
  self->pub.fill_input_buffer = my_fill_input_buffer;
  self->pub.skip_input_data = my_skip_input_data;
  self->pub.resync_to_restart = jpeg_resync_to_restart; /* use default method */
  self->pub.term_source = my_term_source;
  self->pub.bytes_in_buffer = length;
  self->pub.next_input_byte = buff;
};


typedef struct {
  PyObject_HEAD

  // This is the python file like object we use to read from:
  PyObject *fd;

  // A python object keeping the input stream:
  PyObject *input;
  
  // The output buffer where we decode the image to
  char *frame;

  // The decompressor object itself (This is also the main talloc context):
  j_decompress_ptr cinfo;

  // Some stats about this image:
  uint32_t x0,y0,x1,y1;
  int row_stride;
} decoder;

static void decoder_dealloc(decoder *self) {
  if(self->cinfo)
    talloc_free(self->cinfo);

  if(self->fd) {
    Py_DECREF(self->fd);
  };

  if(self->input) {
    Py_DECREF(self->input);
  };
    
  self->ob_type->tp_free((PyObject*)self);
}

static int decoder_init(decoder *self, PyObject *args) {
  if(!PyArg_ParseTuple(args, "O", &self->fd))
    return -1;

  self->input = NULL;
  self->cinfo = talloc(NULL, struct jpeg_decompress_struct);
  self->cinfo->err = (struct jpeg_error_mgr *)talloc(self->cinfo, struct my_error_mgr);
  jpeg_std_error(self->cinfo->err);

  self->cinfo->err->error_exit = my_error_exit;
  self->cinfo->err->output_message = my_output_message;

  Py_INCREF(self->fd);

  // The decoded frame
  self->frame = NULL;

  return 0;
}

static PyObject *decoder_decode(decoder *self, PyObject *args) {
  int32_t len;
  PyObject *result;
  unsigned char *buf;
  JSAMPROW row_pointer[1];      /* pointer to JSAMPLE row[s] */
  char *empty_line;

  if(!PyArg_ParseTuple(args, "i", &len)) return NULL;

  // Make sure to free previously held encoded frames:
  if(self->input) {
    Py_DECREF(self->input);
  };

  // Fetch new data from our fd:
  result = PyObject_CallMethod(self->fd, "seek", "(k)", 0);
  if(!result)
    return NULL;

  Py_DECREF(result);

  self->input = PyObject_CallMethod(self->fd, "read", "(i)", len);
  if(self->input == NULL) return NULL;

  if (setjmp(((struct my_error_mgr *)self->cinfo->err)->setjmp_buffer)) {
    /* If we get here, the JPEG code has signaled an error.
     * We need to clean up the JPEG object, close the input file, and return.
     */
    goto abort;
  }

  // Build a new decompressor object:
  if(PyString_AsStringAndSize(self->input,(char **) &buf, &len)<0) return NULL;

  jpeg_create_decompress(self->cinfo);
  jpeg_my_src(self->cinfo, buf, len);

  // Decode the data:
  jpeg_read_header(self->cinfo, TRUE);
  jpeg_start_decompress(self->cinfo);

  self->row_stride = self->cinfo->output_width * self->cinfo->output_components;

  // An empty line for comparison
  empty_line = alloca(self->row_stride);
  memset(empty_line, 0x80, self->row_stride);
  
  // Make sure we have enough space:
  {
    int buffer_size = self->row_stride * self->cinfo->output_height;
    self->frame = talloc_realloc(self->cinfo, self->frame, char, buffer_size);
    
    memset(self->frame, 0x80, buffer_size);
  };

  while (self->cinfo->output_scanline < self->cinfo->output_height) {
    // Calculate where this line needs to go.
    row_pointer[0] = (unsigned char *)self->frame + 
      self->cinfo->output_scanline * self->row_stride;

    jpeg_read_scanlines(self->cinfo, row_pointer, 1);

    // This allows us to quit earlier - a performance optimization
    if(!memcmp(empty_line, row_pointer[0], self->row_stride)) 
      goto abort;
  };

  jpeg_finish_decompress(self->cinfo);
  Py_RETURN_NONE;

 abort:
  jpeg_abort_decompress(self->cinfo);
  jpeg_destroy_decompress(self->cinfo);
  printf("Decoded %u lines\n", self->cinfo->output_scanline);
  return PyErr_Format(PyExc_RuntimeError, "Jpeg Decompressor error");
};

static PyObject *py_find_frame_bounds(decoder *self, PyObject *args) {
  uint32_t i,j;
  int frame_size = self->cinfo->output_height * self->row_stride;

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
    self->y1 = i/self->row_stride - 7;
    self->x1 = (i % self->row_stride) / self->cinfo->output_components;
  };

  return Py_BuildValue("(ii)", self->x1, self->y1);
};

/** Calculates the integral on self->frame, between left and right
    between row and row-1. Note that left,right and row are given in
    pixels. 
*/
static int calculate_integral(decoder *self, int row, int left, int right) {
  int result=0;
  int i;

  for(i= left * self->cinfo->output_components;
      i < right * self->cinfo->output_components; i++) {
    result += abs(self->frame[(row) * self->row_stride + i] - 
		  self->frame[(row-1) * self->row_stride + i]);
  };

  // Try to normalise the result wrt the width calculated
  //result = result / (right - left);
  //  printf("Integral on row %u (%u-%u) is %u\n", row, left, right, result);
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

  int scale = self->cinfo->output_width * 100 / abs(left - right);

  // Result scaled to 100 - 100 means the integral for this value is
  // exactly the average of the previous and next row
  // return value * 10000 / expected_value / scale;
  return value / scale;
};

static PyObject *py_find_discontinuity(decoder *self, PyObject *args) {
  int32_t len;
  PyObject *result;
  unsigned int max_estimate = 0;
  unsigned int max_row = 0;

  if(!PyArg_ParseTuple(args, "i", &len)) return NULL;

  // First decode the current frame:
  result = PyObject_CallMethod((PyObject *)self, "decode", "(i)", len);
  // Catch and ignore runtime exceptions:
  if(PyErr_Occurred() && PyErr_ExceptionMatches(PyExc_RuntimeError)) {
    PyErr_Clear();
  } else {
    Py_DECREF(result);
  };

  {
    int i;
    
    for(i=8; i<self->cinfo->output_height; i+=1) {
      unsigned int estimate = estimate_row(self, i, 0, self->cinfo->output_width);

      //      printf("Row estimate at %u, %u\n", i,estimate);
      if(estimate > max_estimate) {
	max_estimate = estimate;
	max_row = i;
      };
    };
  };
  
  return Py_BuildValue("(ll)", max_row, max_estimate);
};

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
  return Py_BuildValue("i", ((my_error_ptr)(self->cinfo->err))->pub.num_warnings);
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

  m = Py_InitModule("jpeg", JpegMethods);

  decoderType.tp_new = PyType_GenericNew;
  if (PyType_Ready(&decoderType) < 0)
    return;

  Py_INCREF(&decoderType);
  PyModule_AddObject(m, "decoder", (PyObject *)&decoderType);
};
