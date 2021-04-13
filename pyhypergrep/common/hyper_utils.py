"""Utilities for scanning text files with Intel Hyperscan"""

import ctypes
import os

from typing import Callable

_INTEL_HYPERSCAN_LIB = None
_HYPERSCANNER_LIB = None
_ZSTD_LIB = None

# C function type used by hyperscanner to send lines back to the python.
HYPERSCANNER_CALLBACK_TYPE = ctypes.CFUNCTYPE(
    None,
    ctypes.c_ulonglong,
    ctypes.c_uint,
    ctypes.c_char_p,
    use_errno=False,
    use_last_error=False
)


def _get_hyperscan_lib() -> ctypes.cdll:
    """Lazily load the Intel Hyperscan library to allow use in subprocesses.

    This library will only be used if libhs is not already installed on the system.
    This behaves similar to a module property in that it will only load if not previously loaded.
    """
    global _INTEL_HYPERSCAN_LIB
    if _INTEL_HYPERSCAN_LIB is None:
        # Load and cache the Hyperscan library to prevent repeat loads within the process.
        parent = os.path.abspath(os.path.dirname(__file__))
        lib_path = os.path.join(parent, 'shared', 'libhs.so.5.4.0')
        _INTEL_HYPERSCAN_LIB = ctypes.cdll.LoadLibrary(lib_path)
    return _INTEL_HYPERSCAN_LIB


def _get_hyperscanner_lib() -> ctypes.cdll:
    """Lazily load the Hyperscanner library, which relies on Intel Hyperscan, to allow use in subprocesses.

    This behaves similar to a module property in that it will only load if not previously loaded.
    """
    global _HYPERSCANNER_LIB
    if _HYPERSCANNER_LIB is None:
        # Load and cache the hyperscanner library to prevent repeat loads within the process.
        parent = os.path.abspath(os.path.dirname(__file__))
        lib_path = os.path.join(parent, 'shared', 'libhyperscanner.so')
        _HYPERSCANNER_LIB = ctypes.cdll.LoadLibrary(lib_path)
    return _HYPERSCANNER_LIB


def _get_zstd_lib() -> ctypes.cdll:
    """Lazily load the ZSTD library to allow use in subprocesses.

    This library will only be used if libzstd is not already installed on the system.
    This behaves similar to a module property in that it will only load if not previously loaded.
    """
    global _ZSTD_LIB  # pylint: disable=global-statement
    if _ZSTD_LIB is None:
        # Load and cache the ZSTD library to prevent repeat loads within the process.
        parent = os.path.abspath(os.path.dirname(__file__))
        lib_path = os.path.join(parent, 'shared', 'libzstd.so.1.4.9')
        _ZSTD_LIB = ctypes.cdll.LoadLibrary(lib_path)
    return _ZSTD_LIB


def hyperscan(path: str, patterns: list, callback: Callable, buffer_size: int = 65535) -> int:
    """Read a text file for regex patterns using Intel Hyperscan.

    Supports GZIP, ZSTD, and Plain Text files.

    Args:
        path: Location of the file to be read by hyperscan.
        patterns: Regex patterns in text format used to match lines.
        callback: Where every regex hit (line index, pattern id, and byte string) are sent.
            Must match HYPERSCANNER_CALLBACK_TYPE.
        buffer_size: How large of a buffer to use while reading in chars. Reads up to first newline or len - 1.

    Returns:
        Response code received from the C backend if there was a failure, 0 otherwise.
    """
    # C string arrays must be created by performing the following:
    # 1. Convert all strings to bytes.
    # 2. Find the C char pointer class for the array length, i.e. a list of 29 strings is a c_char_p_Array_29
    # 3. Assign the pointer for the byte list to every position in the C array to mimic a C array of char pointers.
    encoded_patterns = []
    for pattern in patterns:
        if not pattern:
            # Hyperscanner does not allow empty strings for matching, prevent attempts to use.
            raise ValueError(f'Invalid pattern "{pattern}" found. Please provide a valid regex for Intel Hyperscan.')
        encoded_patterns.append(pattern.encode())
    pattern_array = (ctypes.c_char_p * (len(encoded_patterns)))()
    pattern_array[:] = encoded_patterns

    # Cache ZSTD/Hyperscan libraries first to provide hyperscanner lib fallback to static builds.
    # These will only be used if the OS does not have the libraries installed already.
    _get_zstd_lib()
    _get_hyperscan_lib()
    # Load and keep reference to the hyperscanner library to allow calling the functions.
    hyperscanner_lib = _get_hyperscanner_lib()

    callback = HYPERSCANNER_CALLBACK_TYPE(callback)
    ret_code = hyperscanner_lib.hyperscan(path.encode(), pattern_array, len(pattern_array), callback, buffer_size)
    return ret_code
