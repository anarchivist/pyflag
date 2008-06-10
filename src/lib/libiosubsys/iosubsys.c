/*
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Tue Jun 10 13:18:41 EST 2008$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************

This is the python binding for the io subsystem.
*/

#include <Python.h>
#include "structmember.h"
#include "libiosubsys.h"
#include "except.h"

typedef struct {
    PyObject_HEAD
    IOSource driver;
    unsigned long long size;
} iosource;

PyObject *map_exceptions_for_python(enum _exception e) {
  switch(e) {
  case E_OVERFLOW:
    return(PyExc_OverflowError);
  case E_IOERROR:
    return(PyExc_IOError);
    case E_NOMEMORY:
      return(PyExc_MemoryError);
  case E_GENERIC:
  default:
    return (PyExc_Exception);
  };
};

PyObject *map_errors_for_python() {
  switch(_global_error) {
  case EOverflow:
    return(PyExc_OverflowError);
  case EIOError:
    return(PyExc_IOError);
    case ENoMemory:
      return(PyExc_MemoryError);
  case EGeneric:
  default:
    return (PyExc_Exception);
  };
};

static void iosource_dealloc(iosource *self) {
    if(self->driver)
        talloc_free(self->driver);
    self->ob_type->tp_free((PyObject*)self);
}

static int iosource_init(iosource *self, PyObject *args, PyObject *kwds) {
  char *keywords[] = { "opts", NULL};
  char *drivername;
  PyObject *opts = NULL;
  IOOptions options = NULL;
  PyObject *tmp;

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "|O", keywords,
				  &opts)) {
    return -1;
  };

  if(!PyList_Check(opts)) {
    PyErr_Format(PyExc_TypeError, "Options must be a list of tuples");
    return -1;
  };

  if(!opts) {
    PyErr_Format(PyExc_Exception, "No options provided to driver");
    return -1;
  };

  options = CONSTRUCT(IOOptions, IOOptions, add, NULL, NULL, NULL, NULL);
  {
    int i=0;

    for(i=0;i<PyList_Size(opts);i++) {
      PyObject *temp,*key,*value;
      char *keyc, *valuec;

      temp = PyList_GetItem(opts,i); 
      if(!PyList_Check(temp)) {
	tmp = PyObject_Str(temp);
	PyErr_Format(PyExc_TypeError, "Element must be a list, not %s", PyString_AsString(tmp));
	Py_DECREF(tmp);
	return -1;
      };

      key = PyList_GetItem(temp,0);
      if(!key) return -1;

      value = PyList_GetItem(temp,1);
      if(!value) return -1;

      key = PyObject_Str(key);
      keyc = PyString_AsString(key);
      if(!keyc) {
	talloc_free(options);
	PyErr_Format(PyExc_Exception, "Not a string - driver options must be encoded as strings.");
    return -1;
      };

      value = PyObject_Str(value);
      valuec= PyString_AsString(value);
      if(!valuec) {
	talloc_free(options);
	PyErr_Format(PyExc_Exception, "Not a string - driver options must be encoded as strings.");
    return -1;
      };

      CONSTRUCT(IOOptions, IOOptions, add,options, options, keyc, valuec);
    };
  };

  drivername = CALL(options, get_value, "subsys");
  if(!drivername) {
    PyErr_Format(PyExc_TypeError, "No iodriver specified");
    return -1;
  };

  TRY {
    self->driver = iosubsys_Open(drivername, options);
  } EXCEPT(E_ANY) {
    talloc_free(options);
    PyErr_Format(map_exceptions_for_python(__EXCEPT__), "Unable to open iosource");
    return -1;
  };

  // We failed to instantiate this driver
  if(!self->driver) {
    talloc_free(options);
    PyErr_Format(map_errors_for_python(), "%s", _error_buff);
    return -1;
  };

  //Check that all the options have been consumed:
  if(!list_empty(&options->list)) {
    IOOptions first;
    list_next(first, &options->list, list);

    PyErr_Format(PyExc_RuntimeError, "Subsystem %s does not accept parameter %s", drivername,
		 first->name);
    talloc_free(options);
    return -1;
  };

  //Now ensure that the options are stolen to the iosource:
  talloc_steal(self->driver, options);
  self->size = self->driver->size;

  return 0;
};

static PyObject *iosource_read_random(iosource *self, PyObject *args) {
  uint32_t len;
  uint64_t offs;
  PyObject *result;
  int length;

  if(!PyArg_ParseTuple(args, "lL", &len, &offs)) 
    return NULL;

  // Allocate some space for the request:
  result=PyString_FromStringAndSize(NULL, len);
  if(!result) return NULL;

  TRY {
    length=self->driver->read_random(self->driver, PyString_AsString(result), len, offs);
  } EXCEPT(E_ANY) {
    Py_DECREF(result);
    return PyErr_Format(PyExc_IOError, "%s",except_str);
  };

  // If we returned less data than was requested - we need to resize
  // the string back
  if(length < len) 
    if(_PyString_Resize(&result,length)<0)
      return NULL;
  
  return result;
};

static PyMemberDef iosource_members[] = {
    {"size", T_ULONG, offsetof(iosource, size), 0,
     "iosource size"},
    {NULL}  /* Sentinel */
};

static PyMethodDef iosource_methods[] = {
    {"read_random", (PyCFunction)iosource_read_random, METH_VARARGS,
     "read data from given offset" },
    {NULL}  /* Sentinel */
};

static PyTypeObject iosourceType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /* ob_size */
    "iosubsys.iosource",       /* tp_name */
    sizeof(iosource),          /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)iosource_dealloc, /* tp_dealloc */
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
    "IOSource Object",         /* tp_doc */
    0,	                       /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    iosource_methods,          /* tp_methods */
    iosource_members,          /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)iosource_init,   /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};

static PyMethodDef IOMethods[] = {
  {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initiosubsys(void) {
    PyObject *m;

    m = Py_InitModule("iosubsys", IOMethods);

    /* setup skfs type */
    iosourceType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&iosourceType) < 0)
        return;

    Py_INCREF(&iosourceType);
    PyModule_AddObject(m, "iosource", (PyObject *)&iosourceType);
}
