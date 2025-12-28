# how2python
Repository to keep track of python memory corruption bugs that can be used to potentially bypass audit hooks

# Bugs
All exploits were tested on 64 bit versions of python on Windows and Linux and on versions >=3.13.0. Exploits might not work or need to be implemented differently on different versions of python.

All files with an exploit implemented will create a bytearray object that can write anywhere in memory which is enough to consider the process "pwned". As a simple PoC, once the object is created it will print its type, length, and overwrite the value of 250 to be 100 and print it out to show that everything has worked.

|Link|Introduced In|Patched In|Exploit Implemented|
|-|-|-|-|
|[\_\_classdict\_\_ bug](./bugs/classdict_bug.py)|3.12.0|N/A|Yes|
|[bytearray bug](./bugs/bytearray_bug.py)||[3.13.6](https://github.com/python/cpython/pull/132379)|Yes|
|[calliter bug](./bugs/calliter_bug.py)||N/A|Yes|
|[cell bug](./bugs/cell_bug.py)||3.13.1|Yes|
|[decimal.Context Bug](./bugs/decimal_context_bug.py)||N/A|Yes|
|[divmod bug](./bugs/divmod_bug.py)||N/A|Yes|
|[functools.partial bug](./bugs/partial_bug.py)|[3.12.3](https://github.com/python/cpython/commit/8f5be78bce95deb338e2e1cf13a0a579b3b42dd2)|N/A|Yes|
|[GenericAlias repr bug](./bugs/ga_repr_bug.py)|3.12.0|N/A|Yes|
|[GenericAlias subscript bug](./bugs/ga_subscr_bug.py)|3.11.0|[3.13.8](https://github.com/python/cpython/pull/138482)|Yes|
|[iter bug](./bugs/iter_bug.py)||N/A|Yes|
|[io.BytesIO bug](./bugs/bytesio_bug.py)|3.12.0|N/A|Yes|
|[itertools.accumulate bug](./bugs/accumulate_bug.py)||N/A|Yes|
|[itertools.count bug](./bugs/count_bug.py)||N/A|Yes|
|[itertools.groupby bug](./bugs/groupby_bug.py)||N/A|Yes|
|[longrange bug](./bugs/longrange_bug.py)||N/A|Yes|
|[mappingproxy bug](./bugs/mappingproxy_bug.py)||N/A|Yes|
|[memoryview richcompare bug](./bugs/memoryview_cmp_bug.py)||N/A|Yes|
|[memoryview subscript bug](./bugs/memoryview_subscr_bug.py)||N/A|Yes|
|[mro bug](./bugs/mro_bug.py)|3.10.0|[3.14.0](https://github.com/python/cpython/pull/127924)|Yes|
|[namespace bug](./bugs/namespace_bug.py)||N/A|Yes|
|[OrderedDict copy bug](./bugs/ordereddict_copy_bug.py)|[3.5.0](https://github.com/python/cpython/commit/96c6af9b207c188c52ac53ce87bb7f2dea3f328b)|N/A|Linux only|
|[OSError bug](./bugs/oserror_bug.py)||N/A|Yes|
|[try/except* bug](./bugs/try_except_star_bug.py)|3.11.0|3.13.2|Yes|

# Notes on 3.14
Most of the bugs in this repository were found during the time when 3.13.0 and 3.13.1 were the most recent python versions, so most exploits are built to work on those versions.

With 3.14, most unpatched bugs should work fine, but a couple of the type confusion bugs will be broken because of the tuple struct change.

A new field was added to the tuple struct which means the `complex` object is no longer the ideal type for creating fake tuples. Very tragic, but life goes on. Maybe you as the reader can find a way to implement these bugs in 3.14 as a learning exercise!

[3.13.0 PyTupleObject](https://github.com/python/cpython/blob/v3.13.0/Include/cpython/tupleobject.h#L5-L11)
[3.14.0 PyTupleObject](https://github.com/python/cpython/blob/v3.14.0/Include/cpython/tupleobject.h#L5-L13)
