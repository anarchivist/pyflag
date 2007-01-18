//#include "class.h"
#include "trie.h"
#include <Python.h>
#include "structmember.h"

typedef struct {
    PyObject_HEAD
    RootNode root;
} trie_index;

static void trie_index_dealloc(trie_index *self) {
    if(self->root)
        talloc_free(self->root);
    self->ob_type->tp_free((PyObject*)self);
}

static int trie_index_init(trie_index *self, PyObject *args) {
    self->root = CONSTRUCT(RootNode, RootNode, Con, NULL);
    if(self->root==NULL)
        return -1;

    return 0;
}

static PyObject *trie_index_add_word(trie_index *self, PyObject *args) {
    int type;
    int value;
    char *word;
    int length;

    if(!PyArg_ParseTuple(args, "s#ii", &word, &length, &value, &type)) 
        return NULL;

    self->root->super.AddWord((TrieNode)self->root, &word, &length,value,type);

    Py_INCREF(Py_None);
    return Py_None;
};

static PyObject *trie_index_index_buffer(trie_index *self, PyObject *args) {
    char *buffer;
    int length;
    int i;
    PyObject *result, *match_list;

    if(!PyArg_ParseTuple(args, "s#", &buffer, &length)) 
        return NULL;

    result = PyList_New(0);
    match_list = PyList_New(0);

    for(i=0; i<length; i++) {
        char *new_buffer = buffer+i;
        int new_length = length-i;
        PyObject *tmp;

        if(self->root->super.Match((TrieNode)self->root, new_buffer, 
		                            &new_buffer, &new_length, match_list)) {

            /** Append temp to the result. Note that match_list is given to tmp */
            tmp = Py_BuildValue("iN",i,match_list);
            if(PyList_Append(result, tmp)<0) {
	            Py_DECREF(tmp);
	            Py_DECREF(result);
	            return NULL;
            }

            Py_DECREF(tmp);
            // Make a new match_list
            match_list=PyList_New(0);
        }
    }

    Py_DECREF(match_list);
    return(result);
}

static PyMemberDef trie_index_members[] = {
    {"WORD_LITERAL", T_INT, WORD_LITERAL, 0,
     "literal word type"},
    {"WORD_EXTENDED", T_INT, WORD_EXTENDED, 0,
     "extended (regex) word type"},
    {"WORD_ENGLISH", T_INT, WORD_ENGLISH, 0,
     "english word type"},
    {NULL}  /* Sentinel */
};

static PyMethodDef trie_index_methods[] = {
    {"add_word", (PyCFunction)trie_index_add_word, METH_VARARGS,
     "Add a word to the trie" },
    {"index_buffer", (PyCFunction)trie_index_index_buffer, METH_VARARGS,
     "index the given buffer" },
    {NULL}  /* Sentinel */
};

static PyTypeObject trie_indexType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /* ob_size */
    "index.Index",             /* tp_name */
    sizeof(trie_index),        /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)trie_index_dealloc, /* tp_dealloc */
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
    "Indexer Object",          /* tp_doc */
    0,	                       /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    trie_index_methods,        /* tp_methods */
    trie_index_members,        /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)trie_index_init, /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};

static PyMethodDef IndexMethods[] = {
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initindex(void) {

    PyObject *m;
#ifdef __DEBUG_V_
    talloc_enable_leak_report_full();
#endif

    m = Py_InitModule("index", IndexMethods);

    /* setup skfs type */
    trie_indexType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&trie_indexType) < 0)
        return;

    Py_INCREF(&trie_indexType);
    PyModule_AddObject(m, "Index", (PyObject *)&trie_indexType);
}
