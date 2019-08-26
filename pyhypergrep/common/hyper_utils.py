"""Utilities for scanning text files with Intel Hyperscan"""

import ctypes
import os

from typing import Callable

_INTEL_HYPERSCAN_LIB = None
_HYPERSCANNER_LIB = None

# C function type used by hyperscanner to send lines back to the python.
HYPERSCANNER_CALLBACK_TYPE = ctypes.CFUNCTYPE(
    None,
    ctypes.c_ulonglong,
    ctypes.c_uint,
    ctypes.c_char_p,
    use_errno=False,
    use_last_error=False
)


def _get_intel_hyperscan() -> ctypes.cdll:
    """Lazily load the Intel Hyperscan library to allow use in subprocesses.

    This behaves similar to a module property in that it will only load if not already loaded before returning.
    """
    global _INTEL_HYPERSCAN_LIB
    if _INTEL_HYPERSCAN_LIB is None:
        # Load Intel Hyperscan library first to prevent hyperscanner from searching local system.
        parent = os.path.abspath(os.path.dirname(__file__))
        lib_path = os.path.join(parent, 'shared', 'libhs.so.5')
        _INTEL_HYPERSCAN_LIB = ctypes.cdll.LoadLibrary(lib_path)
    return _INTEL_HYPERSCAN_LIB


def _get_hyperscanner() -> ctypes.cdll:
    """Lazily load the Hyperscanner library, which relies on Intel Hyperscan, to allow use in subprocesses.

    This behaves similar to a module property in that it will only load if not already loaded before returning.
    """
    global _HYPERSCANNER_LIB
    if _HYPERSCANNER_LIB is None:
        # Load and cache the hyperscanner library to prevent repeat loads within the process.
        parent = os.path.abspath(os.path.dirname(__file__))
        lib_path = os.path.join(parent, 'shared', 'libhyperscanner.so')
        _HYPERSCANNER_LIB = ctypes.cdll.LoadLibrary(lib_path)
    return _HYPERSCANNER_LIB


def hyperscan(path: str, patterns: list[str], callback: Callable) -> int:
    """Read a text file for regex patterns using Intel Hyperscan.

    Supports GZIP and Plain Text files.

    Args:
        path: Location of the file to be read by hyperscan.
        patterns: Regex patterns in text format used to match lines.
        callback: Where the line index, pattern id, and line as bytes. Must match HYPERSCANNER_CALLBACK_TYPE.

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

    # Call without saving reference to Intel Hyperscan library first to prevent other libs from searching OS.
    _get_intel_hyperscan()
    # Load and keep reference to the hyperscanner library to allow calling the functions.
    hyperscanner_lib = _get_hyperscanner()

    ret_code = hyperscanner_lib.hyperscan(path.encode(), pattern_array, len(pattern_array), callback)
    return ret_code
