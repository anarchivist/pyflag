/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 2; tab-width: 2 -*- */
/** This is a heavily modified version of the original py_GeoIP.c
		released by MaxMind. The original version has an odd interface and
		many bugs. This version should be much more pythonic.
*/

/* py_GeoIP.c
 *
 * Copyright (C) 2003 MaxMind LLC
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <Python.h>
#include "GeoIP.h"
#include "GeoIPCity.h"

staticforward PyTypeObject GeoIP_GeoIPType;

typedef struct {
  PyObject_HEAD;
  GeoIP *gi;
} GeoIPObject;

/** Here if we fail to open the file we raise an IOError as is
		customery in python. The original module returned None.

		We also ask callers to tell us what type of database they expect
		so we can check it right here. The original code would not
		indicate an error until it was time to read the handle, at which
		time it was way too late. For example it was possible to do:

		a = GeoIP("/etc/passwd")

		without an exception raised until we actually tried to query it.

		The GEOIP_STANDARD is the default here - so this parameter is
		optional.

		The expected_type arg indicates which type of db we expect.
*/
static int GeoIP_init(GeoIPObject* self, PyObject *args) {
  char * filename;
  int flags=0;
	int expected_type;

	if (!PyArg_ParseTuple(args, "si|i", &filename, &expected_type, &flags)) {
    return -1;
  }

  self->gi = GeoIP_open(filename, flags);

	// We need to raise a proper python Exception - the original code
	// just returned NULL which is incorrect because GeoIP_open does not
	// properly set the exception state:
  if (!self->gi) {
		PyErr_Format(PyExc_IOError, "Cant open file %s", filename);
    return -1;
  };

	// We need to verify that this database is something we can handle
	if(self->gi->databaseType != expected_type) {
		PyErr_Format(PyExc_IOError, "This file is not of the expected type");
		return -1;
	};

	return 0;
}

static void
GeoIP_dealloc(GeoIPObject* self)
{
	if(self->gi)
		GeoIP_delete(self->gi);

  self->ob_type->tp_free((PyObject*)self);
};

static PyObject * GeoIP_country_code_by_name_Py(GeoIPObject *self, PyObject *args) {
  char * name;
  const char * retval;
  if (!PyArg_ParseTuple(args, "s", &name)) {
    return NULL;
  };

  retval = GeoIP_country_code_by_name(self->gi, name);
  return Py_BuildValue("s", retval);
}

static PyObject * GeoIP_country_name_by_name_Py(GeoIPObject *self, PyObject *args) {
  char * name;
  const char * retval;

  if (!PyArg_ParseTuple(args, "s", &name)) {
    return NULL;
  }
  retval = GeoIP_country_name_by_name(self->gi, name);
  return Py_BuildValue("s", retval);
}

static PyObject * GeoIP_country_code_by_addr_Py(GeoIPObject *self, PyObject *args) {
  char * name;
  const char * retval;

  if (!PyArg_ParseTuple(args, "s", &name)) {
    return NULL;
  }

  retval = GeoIP_country_code_by_addr(self->gi, name);
  return Py_BuildValue("s", retval);
}

static PyObject * GeoIP_country_name_by_addr_Py(GeoIPObject *self, PyObject *args) {
  char * name;
  const char * retval;

  if (!PyArg_ParseTuple(args, "s", &name)) {
    return NULL;
  }
  retval = GeoIP_country_name_by_addr(self->gi, name);
  return Py_BuildValue("s", retval);
}

static PyObject * GeoIP_org_by_addr_Py(GeoIPObject *self, PyObject *args) {
  char * name;
  const char * retval;

  if (!PyArg_ParseTuple(args, "s", &name)) {
    return NULL;
  }
  retval = GeoIP_org_by_addr(self->gi, name);
  return Py_BuildValue("s", retval);
}

static PyObject * GeoIP_org_by_name_Py(GeoIPObject *self, PyObject *args) {
  char * name;
  const char * retval;

  if (!PyArg_ParseTuple(args, "s", &name)) {
    return NULL;
  }
  
	retval = GeoIP_org_by_name(self->gi, name);
  return Py_BuildValue("s", retval);
}

int GeoIP_SetItemString(PyObject *dict, const char * name, char * value) {
	PyObject * valueObj;
	int result;

	valueObj = Py_BuildValue("s", value);
	result = PyDict_SetItemString(dict, name, valueObj);
	Py_DECREF(valueObj);

	return result;
}

void GeoIP_SetItemFloat(PyObject *dict, const char * name, float value) {
	PyObject * nameObj;
	PyObject * valueObj;
	nameObj = Py_BuildValue("s",name);
	valueObj = Py_BuildValue("f",value);
	PyDict_SetItem(dict,nameObj,valueObj);
	Py_DECREF(nameObj);
	Py_DECREF(valueObj);
}

void GeoIP_SetItemInt(PyObject *dict, const char * name, int value) {
	PyObject * nameObj;
	PyObject * valueObj;
	nameObj = Py_BuildValue("s",name);
	valueObj = Py_BuildValue("i",value);
	PyDict_SetItem(dict,nameObj,valueObj);
	Py_DECREF(nameObj);
	Py_DECREF(valueObj);
}

static PyObject * GeoIP_region_populate_dict(GeoIPRegion * gir) {
  PyObject * retval;
  retval = PyDict_New();
  GeoIP_SetItemString(retval,"country_code",gir->country_code);
  GeoIP_SetItemString(retval,"region",gir->region);
  GeoIPRegion_delete(gir);
  return retval;
}

static PyObject * GeoIP_populate_dict(GeoIPRecord *gir) {
	PyObject * retval;
	retval = PyDict_New();
	GeoIP_SetItemString(retval,"country_code",gir->country_code);
	GeoIP_SetItemString(retval,"country_code3",gir->country_code3);
	GeoIP_SetItemString(retval,"country_name",gir->country_name);
	GeoIP_SetItemString(retval,"region",gir->region);
	GeoIP_SetItemString(retval,"city",gir->city);
	GeoIP_SetItemString(retval,"postal_code",gir->postal_code);
	GeoIP_SetItemFloat(retval,"latitude",gir->latitude);
	GeoIP_SetItemFloat(retval,"longitude",gir->longitude);
	GeoIP_SetItemInt(retval,"dma_code",gir->dma_code);
	GeoIP_SetItemInt(retval,"area_code",gir->area_code);
	GeoIPRecord_delete(gir);
	return retval;
}

static PyObject * GeoIP_record_by_addr_Py(GeoIPObject *self, PyObject *args) {
  char * addr;
  GeoIPRecord * gir;

  if (!PyArg_ParseTuple(args, "s", &addr)) {
    return NULL;
  }

  gir = GeoIP_record_by_addr(self->gi, addr);

	// Properly set the exception state here...
	if (gir == NULL) {
		return PyErr_Format(PyExc_KeyError, "Unable to find record for %s", addr);
	}

	return GeoIP_populate_dict(gir);
}

static PyObject * GeoIP_record_by_name_Py(GeoIPObject *self, PyObject *args) {
  char * name;
  GeoIPRecord * gir;

  if (!PyArg_ParseTuple(args, "s", &name)) {
    return NULL;
  };

	// Properly set the exception state here...
  gir = GeoIP_record_by_name(self->gi, name);
	if (gir == NULL) {
		return PyErr_Format(PyExc_KeyError, "Unable to find record for %s", name);
	};

	return GeoIP_populate_dict(gir);
}

static PyObject * GeoIP_region_by_name_Py(GeoIPObject *self, PyObject * args) {
  char * name;
  GeoIPRegion * retval;

  if (!PyArg_ParseTuple(args, "s", &name)) {
    return NULL;
  };

	// Properly set the exception state here...
  retval = GeoIP_region_by_name(self->gi, name);
	if(!retval)
		return PyErr_Format(PyExc_KeyError, "Unable to find record for %s", name);  

	return GeoIP_region_populate_dict(retval);
}

static PyObject * GeoIP_region_by_addr_Py(GeoIPObject *self, PyObject * args) {
  char * name;
  GeoIPRegion * retval;

  if (!PyArg_ParseTuple(args, "s", &name)) {
    return NULL;
  }

  retval = GeoIP_region_by_addr(self->gi, name);
	if(!retval)
 		return PyErr_Format(PyExc_KeyError, "Unable to find record for %s", name);

  return GeoIP_region_populate_dict(retval);
}

static PyMethodDef GeoIP_Object_methods[] = {
  {"country_code_by_name", (PyCFunction)GeoIP_country_code_by_name_Py, 
	 METH_VARARGS, "Lookup Country Code By Name"},
  {"country_name_by_name", (PyCFunction)GeoIP_country_name_by_name_Py, 
	 METH_VARARGS, "Lookup Country Name By Name"},
  {"country_code_by_addr", (PyCFunction)GeoIP_country_code_by_addr_Py, 
	 METH_VARARGS, "Lookup Country Code By IP Address"},
  {"country_name_by_addr", (PyCFunction)GeoIP_country_name_by_addr_Py, 
	 METH_VARARGS, "Lookup Country Name By IP Address"},
  {"org_by_addr", (PyCFunction)GeoIP_org_by_addr_Py, 
	 METH_VARARGS, "Lookup Organization or ISP By IP Address"},
  {"org_by_name", (PyCFunction)GeoIP_org_by_name_Py, 
	 METH_VARARGS, "Lookup Organization or ISP By Name"},
  {"region_by_addr", (PyCFunction)GeoIP_region_by_addr_Py, 
	 METH_VARARGS, "Lookup Region By IP Address"},
  {"region_by_name", (PyCFunction)GeoIP_region_by_name_Py, 
	 METH_VARARGS, "Lookup Region By Name"},
  {"record_by_addr", (PyCFunction)GeoIP_record_by_addr_Py, 
	 METH_VARARGS, "Lookup City Region By IP Address"},
  {"record_by_name", (PyCFunction)GeoIP_record_by_name_Py, 
	 METH_VARARGS, "Lookup City Region By Name"},
  {NULL, NULL, 0, NULL}
};

static PyTypeObject GeoIP_GeoIPType = {
	PyObject_HEAD_INIT(NULL)
	0,                         /* ob_size */
	"geoip.GeoIP",             /* tp_name */
	sizeof(GeoIPObject),          /* tp_basicsize */
	0,                         /* tp_itemsize */
	(destructor)GeoIP_dealloc, /* tp_dealloc */
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
	"GeoIP Object",      /* tp_doc */
	0,	                       /* tp_traverse */
	0,                         /* tp_clear */
	0,                         /* tp_richcompare */
	0,                         /* tp_weaklistoffset */
	0,                         /* tp_iter */
	0,                         /* tp_iternext */
	GeoIP_Object_methods,          /* tp_methods */
	0,                         /* tp_members */
	0,                         /* tp_getset */
	0,                         /* tp_base */
	0,                         /* tp_dict */
	0,                         /* tp_descr_get */
	0,                         /* tp_descr_set */
	0,                         /* tp_dictoffset */
	(initproc)GeoIP_init,      /* tp_init */
	0,                         /* tp_alloc */
	0,                         /* tp_new */
};

static PyMethodDef GeoIPModuleMethods[] = {
	{NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initgeoip(void) {
  PyObject *m, *d, *tmp;

  m = Py_InitModule("geoip", GeoIPModuleMethods);
  d = PyModule_GetDict(m);

  tmp = PyInt_FromLong(0);
  PyDict_SetItemString(d, "GEOIP_STANDARD", tmp);
  Py_DECREF(tmp);

  tmp = PyInt_FromLong(1);
  PyDict_SetItemString(d, "GEOIP_MEMORY_CACHE", tmp);
  Py_DECREF(tmp);


	GeoIP_SetItemInt(d,"GEOIP_COUNTRY_EDITION"     , 1);
	GeoIP_SetItemInt(d,"GEOIP_REGION_EDITION_REV0" , 7);
	GeoIP_SetItemInt(d,"GEOIP_CITY_EDITION_REV0"   , 6);
	GeoIP_SetItemInt(d,"GEOIP_ORG_EDITION"         , 5);
	GeoIP_SetItemInt(d,"GEOIP_ISP_EDITION"         , 4);
	GeoIP_SetItemInt(d,"GEOIP_CITY_EDITION_REV1"   , 2);
	GeoIP_SetItemInt(d,"GEOIP_REGION_EDITION_REV1" , 3);
	GeoIP_SetItemInt(d,"GEOIP_PROXY_EDITION"       , 8);
	GeoIP_SetItemInt(d,"GEOIP_ASNUM_EDITION"       , 9);
	GeoIP_SetItemInt(d,"GEOIP_NETSPEED_EDITION"    , 10);
	GeoIP_SetItemInt(d,"GEOIP_DOMAIN_EDITION"      , 11);


	GeoIP_GeoIPType.tp_new = PyType_GenericNew;
	if(PyType_Ready(&GeoIP_GeoIPType)<0)
		return;

	Py_INCREF(&GeoIP_GeoIPType);

	PyModule_AddObject(m, "GeoIP", (PyObject *)&GeoIP_GeoIPType);
}
