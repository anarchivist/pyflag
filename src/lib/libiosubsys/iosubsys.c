/*
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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
#include "libiosubsys.h"
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

static PyObject *Open(PyObject *dummy, PyObject *args, PyObject *kwd) {
  char *keywords[] = { "iodriver","opts", NULL};
  PyObject *iodriver=NULL;
  char *drivername;
  PyObject *opts=NULL;
  IOSource driver=NULL;
  IOOptions options = NULL;
  PyObject *tmp;

  if(!PyArg_ParseTupleAndKeywords(args, kwd, "|OO", keywords,
				  &iodriver, &opts)) {
    return NULL;
  };

  if(!PyList_Check(opts))
    return PyErr_Format(PyExc_TypeError, "Options must be a list of tuples");

  if(!iodriver) {
    return PyErr_Format(PyExc_TypeError, "No iodriver specified");
  } else {
    drivername = PyString_AsString(iodriver);
  };

  if(!opts) {
    return PyErr_Format(PyExc_Exception, "No options provided to driver");
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
	return NULL;
      };

      key = PyList_GetItem(temp,0);
      if(!key) return NULL;

      value = PyList_GetItem(temp,1);
      if(!value) return NULL;

      key = PyObject_Str(key);
      keyc = PyString_AsString(key);
      if(!keyc) {
	talloc_free(options);
	return PyErr_Format(PyExc_Exception, "Not a string - driver options must be encoded as strings.");
      };

      value = PyObject_Str(value);
      valuec= PyString_AsString(value);
      if(!valuec) {
	talloc_free(options);
	return PyErr_Format(PyExc_Exception, "Not a string - driver options must be encoded as strings.");
      };

      CONSTRUCT(IOOptions, IOOptions, add,options, options, keyc, valuec);
    };
  };

  TRY {
    driver = iosubsys_Open(drivername, options);
  } EXCEPT(E_ANY) {
    talloc_free(options);
    return PyErr_Format(map_exceptions_for_python(__EXCEPT__), "Unable to open iosource");
  };

  // We failed to instantiate this driver
  if(!driver) {
    talloc_free(options);
    return PyErr_Format(map_errors_for_python(), "%s", _error_buff);
  };

  //Check that all the options have been consumed:
  if(!list_empty(&options->list)) {
    IOOptions first;
    list_next(first, &options->list, list);

    PyErr_Format(PyExc_RuntimeError, "Subsystem %s does not accept parameter %s", drivername,
		 first->name);
    talloc_free(options);
    return NULL;
  };

  //Now ensure that the options are stolen to the iosource:
  talloc_steal(driver, options);

  // Ensure that when the iosource is gced the memeory is freed properly:
  return PyCObject_FromVoidPtr(driver, (void (*)(void *))talloc_free);
};

static PyObject *py_read_random(PyObject *dummy, PyObject *args) {
  uint32_t len;
  uint64_t offs;
  PyObject *py_driver;
  IOSource driver;
  PyObject *result;
  int length;

  if(!PyArg_ParseTuple(args, "OlL", &py_driver, &len, &offs)) 
    return NULL;

  // Check that what we got is actually an iosource driver:
  driver = (IOSource)PyCObject_AsVoidPtr(py_driver);
  if(!driver || !ISSUBCLASS(driver, IOSource)) {
    return PyErr_Format(PyExc_RuntimeError, "This is not an iosource driver");
  };

  // Allocate some space for the request:
  result=PyString_FromStringAndSize(NULL, len);
  if(!result) return NULL;

  TRY {
    length=driver->read_random(driver, PyString_AsString(result), len, offs);
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

static PyObject *size(PyObject *dummy, PyObject *args) {
  PyObject *py_driver;
  IOSource driver;
  if(!PyArg_ParseTuple(args, "O", &py_driver)) 
    return NULL;

  // Check that what we got is actually an iosource driver:
  driver = (IOSource)PyCObject_AsVoidPtr(py_driver);
  if(!driver)     
    return PyErr_Format(PyExc_RuntimeError, "This is not an iosource driver");

  if(!ISSUBCLASS(driver, IOSource)) {
    return PyErr_Format(PyExc_RuntimeError, "This is not an iosource driver - it is a %s", NAMEOF(driver));
  };

  return PyLong_FromUnsignedLongLong(driver->size);
};

static PyMethodDef IOMethods[] = {
  {"Open",  (PyCFunction)Open, METH_VARARGS|METH_KEYWORDS,
   "Create and initialise a new IO Source handle"},
  {"read_random",  (PyCFunction)py_read_random, METH_VARARGS, 
   "Read a random range of memory"},
  {"size",(PyCFunction)size, METH_VARARGS,
   "Get the total size of the source"},
  {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initiosubsys(void) {
  (void) Py_InitModule("iosubsys", IOMethods);
}
