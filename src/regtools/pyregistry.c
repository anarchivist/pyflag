#include <Python.h>
#include <regfi.h>

typedef struct {
  PyObject_HEAD
  REGF_FILE *registry;
  PyObject *fd;
} PyRegistry;

static int PyRegistry_init(PyRegistry *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"fd", NULL};
  PyObject *fd;

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &fd))
    return -1;

  // Take over the fd
  Py_INCREF(fd);
  self->fd = fd;

  //Create a new registry file object
  

  return 0;
};

static void
PyRegistry_dealloc(PyRegistry *self) {
  talloc_free(self->registry);
  Py_DECREF(self->fd);
  self->ob_type->tp_free((PyObject*)self);
}


static PyMethodDef PyRegistry_methods[] = {
  
  { NULL }
};

static PyTypeObject PyRegistryType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /* ob_size */
    "pyregistry.PyRegistry",             /* tp_name */
    sizeof(PyRegistry),          /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)PyRegistry_dealloc, /* tp_dealloc */
    0,                         /* tp_print */
    0,        /* tp_getattr */
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
    "Windows Registry Parser Object",         /* tp_doc */
    0,	                       /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    PyRegistry_methods,          /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)PyRegistry_init, /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};

static PyMethodDef pyregistryMethods[] = {
  {NULL, NULL, 0, NULL}
};

static PyObject *g_module_reference;

PyMODINIT_FUNC initpyregistry(void) {
#ifdef __DEBUG_V_
    talloc_enable_leak_report_full();
#endif

    //This is a talloc reference that all objects will be tied to
    //(because talloc_increase_ref_count is broken).
    g_module_reference = Py_InitModule("pyregistry", pyregistryMethods);

    PyRegistryType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&PyRegistryType) < 0)
        return;

    Py_INCREF(&PyRegistryType);

    PyModule_AddObject(g_module_reference, 
		       "PyRegistry", (PyObject *)&PyRegistryType);
}
