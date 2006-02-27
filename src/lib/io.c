/*
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.75 Date: Sat Feb 12 14:00:04 EST 2005$
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
#include "iosubsys.h"
#include "except.h"

PyObject *map_exceptions_for_python(enum _exception e) {
  switch(e) {
  case E_OVERFLOW:
    return(PyExc_OverflowError);
  case E_IOERROR:
    return(PyExc_IOError);
    case E_NOMEMORY:
      return(PyExc_MemoryError);
  case E_GENERIC:
  case E_ANY:
  default:
    return (PyExc_Exception);
  };
};

static PyObject *py_parse_options(PyObject *dummy, PyObject *args) {
  IO_INFO *io;
  PyObject *pyio;
  char *opts;

  // retrieve args
  if(!PyArg_ParseTuple(args, "Os", &pyio, &opts)) {
    return NULL;
  }

  io=(IO_INFO *)PyCObject_AsVoidPtr(pyio);

  TRY {
    io_parse_options(io,opts);
  } EXCEPT(E_ANY) {
    return PyErr_Format(map_exceptions_for_python(__EXCEPT__), "%s", except_str);
  };

  Py_INCREF(Py_None);
  return Py_None;
};


static PyObject *Open(PyObject *dummy, PyObject *args) {
  char *name;
  IO_INFO *result;

  // retrieve args
  if(!PyArg_ParseTuple(args, "s", &name)) {
    return NULL;
  }

  TRY {
    result=io_open(name);

  } EXCEPT(E_ANY) {
    return PyErr_Format(map_exceptions_for_python(__EXCEPT__), "%s", except_str);
  };

  return PyCObject_FromVoidPtr(result, (void (*)(void *))io_close);
};

static PyObject *py_read_random(PyObject *dummy, PyObject *args) {
  IO_INFO *self;
  PyObject *pyself;
  unsigned int length;
  unsigned long  long int offs;
  char *buf;
  PyObject *string;
  int result;
  PyGILState_STATE gstate;

  // retrieve args
  if(!PyArg_ParseTuple(args, "OIK", &pyself, &length, &offs)) {
    return NULL;
  };

  self = (IO_INFO *)PyCObject_AsVoidPtr(pyself);

  TRY {
    /** Create a new string to return to the caller */
    string =  PyString_FromStringAndSize(NULL, length);
    if(!string) {
      PyGILState_Release(gstate);
      return PyErr_Format(PyExc_MemoryError, "Unable to allocate a string of length %u\n", length);
    }

    buf = PyString_AsString(string);

    /** Release the GIL to allow other threads to work while we wait on IO */
    Py_BEGIN_ALLOW_THREADS
    result=self->read_random(self,buf, length, offs,"Python calling");
    Py_END_ALLOW_THREADS

    /** If this was a short read we truncate the string (This is
	allowed because we just created it) 
    */
    if(result < length)
      if(_PyString_Resize(&string, result) <0 ) return NULL;

  } EXCEPT(E_ANY) {

    PyGILState_Release(gstate);
    return PyErr_Format(map_exceptions_for_python(__EXCEPT__), "%s", except_str);
  };

  /** Return the string to our caller */
  return string;
};

static PyMethodDef IOMethods[] = {
  {"Open",  (PyCFunction)Open, METH_VARARGS,
   "Create and initialise a new IO Source handle"},
  {"read_random",  (PyCFunction)py_read_random, METH_VARARGS, 
   "Read a random range of memory"},
  {"parse_options",  (PyCFunction)py_parse_options, 
   METH_VARARGS, 
   "Parse the options into an IO source"},
/*   {"io_help",  py_io_help, METH_VARARGS,  */
/*    "Returns a help message about the IO Source"}, */
/*   {"io_close",  py_io_close, METH_VARARGS,  */
/*    "Close and discard the IO Source"}, */
  {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initiosubsys(void) {
  (void) Py_InitModule("iosubsys", IOMethods);
}
