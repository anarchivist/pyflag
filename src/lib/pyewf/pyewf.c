#include "Python.h"
#include "libewf.h"

#include <string.h>
#include <stdlib.h>

/******************************************************************
 * pyewf - libewf python binding
 * ***************************************************************/

typedef struct {
    PyObject_HEAD
    LIBEWF_HANDLE *handle;
    char **filenames;
    int numfiles;
    uint64_t readptr;
    uint64_t size;
} ewffile;

static void ewffile_dealloc(ewffile *self);
static int ewffile_init(ewffile *self, PyObject *args, PyObject *kwds);
static PyObject *ewffile_read(ewffile *self, PyObject *args, PyObject *kwds);
static PyObject *ewffile_seek(ewffile *self, PyObject *args, PyObject *kwds);
static PyObject *ewffile_get_header(ewffile *self, PyObject *args, PyObject *kwds);
static PyObject *ewffile_get_headers(ewffile *self);
static PyObject *ewffile_tell(ewffile *self);
static PyObject *ewffile_close(ewffile *self);

static PyMethodDef ewffile_methods[] = {
    {"read", (PyCFunction)ewffile_read, METH_VARARGS|METH_KEYWORDS,
     "Read data from file" },
    {"seek", (PyCFunction)ewffile_seek, METH_VARARGS|METH_KEYWORDS,
     "Seek within a file" },
    {"get_header", (PyCFunction)ewffile_get_header, METH_VARARGS|METH_KEYWORDS,
     "Retrieve an EWF header by name" },
    {"get_headers", (PyCFunction)ewffile_get_headers, METH_NOARGS,
     "Retrieve an EWF header by name" },
    {"tell", (PyCFunction)ewffile_tell, METH_NOARGS,
     "Return possition within file" },
    {"close", (PyCFunction)ewffile_close, METH_NOARGS,
     "Close the file" },
    {NULL}  /* Sentinel */
};

static PyTypeObject ewffileType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /* ob_size */
    "pyewf.ewffile",           /* tp_name */
    sizeof(ewffile),           /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)ewffile_dealloc,/* tp_dealloc */
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
    "libewf File Object",      /* tp_doc */
    0,	                       /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    ewffile_methods,           /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)ewffile_init,    /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};

static void
ewffile_dealloc(ewffile *self) {
	int i;
	if(self->filenames) {
    	for(i=0; i<self->numfiles; i++)
    		free(self->filenames[i]);
    	free(self->filenames);
    }
    self->ob_type->tp_free((PyObject*)self);
}

static int
ewffile_init(ewffile *self, PyObject *args, PyObject *kwds) {
	int i;
	PyObject *files, *tmp;
    static char *kwlist[] = {"files", NULL};

    self->filenames = NULL;
    self->readptr = 0;
    self->numfiles = 0;
    self->size = 0;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &files))
        return -1;

    if(PySequence_Check(files) == 0) {
        PyErr_Format(PyExc_TypeError, "Option must be a list or tuple");
        return -1;
    }

    self->numfiles = PySequence_Size(files);
    self->filenames = (char **) calloc(sizeof(char *), self->numfiles);
    for(i=0; i<self->numfiles; i++) {
    	tmp = PySequence_GetItem(files, i);
    	self->filenames[i] = strdup(PyString_AsString(tmp));
    	Py_DECREF(tmp);
    }

    self->handle = libewf_open(self->filenames, self->numfiles, LIBEWF_OPEN_READ);
    if(self->handle == NULL) {
    	PyErr_Format(PyExc_IOError, "Failed to initialise libewf");
    	return -1;
    }

    libewf_get_media_size(self->handle, &self->size);

    return 0;
}

static PyObject *
ewffile_read(ewffile *self, PyObject *args, PyObject *kwds) {
    int written;
    PyObject *retdata;
    int readlen=-1;

    static char *kwlist[] = {"size", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwlist, &readlen))
        return NULL; 

    /* adjust readlen if size not given or is too big */
    if(readlen < 0 || self->readptr + readlen > self->size)
        readlen = self->size - self->readptr;

    if(readlen < 0) readlen = 0;

    retdata = PyString_FromStringAndSize(NULL, readlen);
    written = libewf_read_buffer(self->handle, PyString_AsString(retdata), readlen);

    if(readlen != written) {
        return PyErr_Format(PyExc_IOError, "Failed to read all data: wanted %d, got %d", readlen, written);
    }

    self->readptr += written;
    return retdata;
}

static PyObject *
ewffile_seek(ewffile *self, PyObject *args, PyObject *kwds) {
    int64_t offset=0;
    int whence=0;
    int hack=0;
    char foo;

    static char *kwlist[] = {"offset", "whence", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "L|i", kwlist, 
                                    &offset, &whence))
        return NULL; 

    switch(whence) {
        case 0:
            self->readptr = offset;
            break;
        case 1:
            self->readptr += offset;
            break;
        case 2:
            self->readptr = self->size + offset;
            if(offset == 0) {
            	hack=1;
            	self->readptr -= 1;
            }
            break;
        default:
            return PyErr_Format(PyExc_IOError, "Invalid argument (whence): %d", whence);
    }

    if(libewf_seek_offset(self->handle, self->readptr) < 0)
        return PyErr_Format(PyExc_IOError, "libewf_seek_offset failed");

    // holy crap this is aweful code!
    if(hack) {
    	libewf_read_buffer(self->handle, &foo, 1);
    }

    Py_RETURN_NONE;
}

static PyObject *
ewffile_tell(ewffile *self) {
    return PyLong_FromLongLong(self->readptr);
}

static PyObject *
ewffile_close(ewffile *self) {
  libewf_close(self->handle);
  Py_RETURN_NONE;
}

/* The following regular headers exist:
 *
 * case_number
 * description
 * examinier_name
 * evidence_number
 * notes
 * acquiry_date
 * system_date
 * acquiry_operating_system
 * acquiry_software_version
 * password
 * compression_type
 * model
 * serial_number
 *
 * The following hashes exist
 * 
 * MD5
 * SHA1
 *
 * The following media information is present:
 *
 * sectors per chunk
 * bytes per sector
 * amount of sectors
 * chunk size
 * error granularity
 * compression values
 * media size
 * media type
 * media flags
 * volume type
 * format
 * guid
 * md5 hash
 * segment filename
 * delta segment filename
 * amount of acquiry errors
 * acquiry error
 * amount of crc errors
 * crc error
 * amount of sessions
 * session
 * write amount of chunks
 * 
 */

// ewfinfo uses 128 bytes, maby thats a max size?
#define HEADER_LENGTH 128

static PyObject *ewffile_get_header(ewffile *self, PyObject *args, PyObject *kwds) {
	int ret;
	PyObject *tmp;
	char buf[HEADER_LENGTH];
	char *identifier=NULL;
    static char *kwlist[] = {"identifier", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &identifier))
        return NULL;

    // this function checks if the headers have already been parsed and
    // returns immediately, so it shouldn't hurt to call it every time.
    libewf_parse_header_values(self->handle, LIBEWF_DATE_FORMAT_CTIME);

    ret = libewf_get_header_value(self->handle, identifier, buf, HEADER_LENGTH);
    if(ret == 0) { // value not present
    	return Py_None;
    }
    else if(ret == -1) {
        return PyErr_Format(PyExc_IOError, "error reading libewf header");
    }

    tmp = PyString_FromString(buf);
    return tmp;
}

static PyObject *ewffile_get_headers(ewffile *self) {
	PyObject *headers, *tmp;
	char **ptr;
	char buf[HEADER_LENGTH];
    char *std_headers[] = {
	    "case_number", "description", "examinier_name",
        "evidence_number", "notes", "acquiry_date",
        "system_date", "acquiry_operating_system",
        "acquiry_software_version", "password",
        "compression_type", "model", "serial_number",
        NULL,
    };

    // this function checks if the headers have already been parsed and
    // returns immediately, so it shouldn't hurt to call it every time.
    libewf_parse_header_values(self->handle, LIBEWF_DATE_FORMAT_CTIME);

    headers = PyDict_New();
    for(ptr = std_headers; *ptr; ptr++) {
        if(libewf_get_header_value(self->handle, *ptr, buf, HEADER_LENGTH) == 1) {
            tmp = PyString_FromString(buf);
            PyDict_SetItemString(headers, *ptr, tmp);
            Py_DECREF(tmp);
        }
    }

    return headers;
}

static PyObject *pyewf_open(PyObject *self, PyObject *args, PyObject *kwds) {
	int ret;
	ewffile *file;
	PyObject *files, *fileargs, *filekwds;
    static char *kwlist[] = {"files", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &files))
        return NULL;

    /* create an ewffile object and return it */
    fileargs = PyTuple_New(0);
    filekwds = Py_BuildValue("{sO}", "files", files);
    if(!filekwds) return NULL;

    file = PyObject_New(ewffile, &ewffileType);
    ret = ewffile_init(file, fileargs, filekwds);
    Py_DECREF(fileargs);
    Py_DECREF(filekwds);

    if(ret == -1) {
        Py_DECREF(file);
        return NULL;
    }
    return (PyObject *)file;
}

/* these are the module methods */
static PyMethodDef pyewf_methods[] = {
    {"open", (PyCFunction)pyewf_open, METH_VARARGS|METH_KEYWORDS,
     "Open encase file (or set of files)" },
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
initpyewf(void) 
{
    PyObject* m;

    /* create module */
    m = Py_InitModule3("pyewf", pyewf_methods, "Python libewf module.");

    /* setup ewffile type */
    ewffileType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&ewffileType) < 0)
        return;

    Py_INCREF(&ewffileType);
    PyModule_AddObject(m, "ewffile", (PyObject *)&ewffileType);
}

