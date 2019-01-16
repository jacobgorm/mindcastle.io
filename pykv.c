#define PY_SSIZE_T_CLEAN
#define NPY_NO_DEPRECATED_API NPY_1_14_API_VERSION
#include <Python.h>
#include <stdint.h>
#include <stdio.h>

#include "kv.h"

static PyObject *PyKVError;

static PyTypeObject PyKVType = { PyVarObject_HEAD_INIT(NULL, 0)
    "pykv.KV"
};

typedef struct {
    PyObject_HEAD
    struct kv kv;
} PyKV;

static PyObject *PyKV_insert(PyKV *self, PyObject * args) {
    uint64_t key;
    const char *value;
    Py_ssize_t size;

    if (!PyArg_ParseTuple(args, "ks#", &key, &value, &size)) {
        PyErr_SetString(PyKVError, "failed to parse tuple");
        return NULL;
    }
    kv_insert(&self->kv, key, (const uint8_t *) value, size);
    Py_RETURN_NONE;
}

static PyObject *PyKV_flush(PyKV *self, PyObject * args) {
    kv_flush(&self->kv);
    Py_RETURN_NONE;
}

static PyObject *PyKV_find(PyKV *self, PyObject * args) {
    uint64_t key;
    if (!PyArg_ParseTuple(args, "k", &key)) {
        PyErr_SetString(PyKVError, "failed to parse tuple");
        return NULL;
    }
    uint8_t *ptr;
    size_t size;
    kv_find(&self->kv, &ptr, &size, key);
    PyObject *ret = PyBytes_FromStringAndSize((char *) ptr, size);
    return ret;
}

static PyMethodDef PyKVMethods[] = {
 { NULL, NULL, 0, NULL }

};
static struct PyModuleDef pykvmodule = {
    PyModuleDef_HEAD_INIT,
    "pykv",   /* name of module */
    NULL, /* module documentation, may be NULL */
    -1,       /* size of per-interpreter state of the module,
                 or -1 if the module keeps state in global variables. */
    PyKVMethods
};


static PyObject *PyKV_init(PyKV * self, PyObject * args) {
    char *prefix;
    if (!PyArg_ParseTuple(args, "s", &prefix)) {
        PyErr_SetString(PyKVError, "wrong init args");
        return NULL;
    }
    if (kv_init(&self->kv, prefix, NULL) < 0) {
        PyErr_SetString(PyKVError, "failed to init pykv");
        return NULL;
    }
    return Py_BuildValue("");
}

static PyObject *PyKV_open(PyKV * self, PyObject * args) {
    char *prefix, *kvinfo;
    if (!PyArg_ParseTuple(args, "ss", &prefix, &kvinfo)) {
        PyErr_SetString(PyKVError, "wrong open args");
        return NULL;
    }

    if (kv_init(&self->kv, prefix, kvinfo) < 0) {
        PyErr_SetString(PyKVError, "failed to init pykv");
        return NULL;
    }
    return Py_BuildValue("");
}

static PyObject *PyKV_save(PyKV * self, PyObject * args) {
    if (!PyArg_ParseTuple(args, "")) {
        PyErr_SetString(PyKVError, "wrong save args");
        return NULL;
    }
    char saved[1024];
    if (kv_save(&self->kv, saved, sizeof(saved)) < 0) {
        PyErr_SetString(PyKVError, "failed to save pykv");
        return NULL;
    }
    return Py_BuildValue("s", saved);
}

static PyMethodDef PyKV_methods[] = {
    { "init", (PyCFunction) PyKV_init, METH_VARARGS, "init"},
    { "open", (PyCFunction) PyKV_open, METH_VARARGS, "open"},
    { "save", (PyCFunction) PyKV_save, METH_VARARGS, "save"},
    { "insert", (PyCFunction) PyKV_insert, METH_VARARGS, "Insert key and value" },
    { "find", (PyCFunction) PyKV_find, METH_VARARGS, "Find key" },
    { "flush", (PyCFunction) PyKV_flush, METH_VARARGS, "Flush inserts" },
    {NULL}  /* Sentinel */
};

static int PyKV_typeinit(PyKV *self, PyObject *args, PyObject *kwds) {
    return 0;
}
static void PyKV_dealloc(PyKV* self) {
    kv_close(&self->kv);
    Py_TYPE(self)->tp_free(self);
}


PyMODINIT_FUNC PyInit_pykv(void) {

    kv_global_init();

    PyObject *m = PyModule_Create(&pykvmodule);
    if (!m) {
        return NULL;
    }
    PyKVError = PyErr_NewException("pykv.error", NULL, NULL);
    Py_INCREF(PyKVError);
    PyModule_AddObject(m, "error", PyKVError);

    PyKVType.tp_new = PyType_GenericNew;
    PyKVType.tp_basicsize = sizeof(PyKV);
    PyKVType.tp_dealloc = (destructor) PyKV_dealloc;
    PyKVType.tp_flags = Py_TPFLAGS_DEFAULT;
    PyKVType.tp_doc = "KV object";
    PyKVType.tp_methods = PyKV_methods;
    PyKVType.tp_init= (initproc) PyKV_typeinit;
    if (PyType_Ready(&PyKVType) < 0) {
        return NULL;
    }

    Py_INCREF(&PyKVType);
    PyModule_AddObject(m, "KV", (PyObject *)&PyKVType);

    return m;
}
