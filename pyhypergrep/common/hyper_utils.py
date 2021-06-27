"""Utilities for scanning text files with Intel Hyperscan"""

import ctypes
import os

from typing import Callable
from typing import List

_INTEL_HYPERSCAN_LIB = None
_HYPERSCANNER_LIB = None
_ZSTD_LIB = None

# Flags pulled from hs_compile.h
HS_FLAG_CASELESS = 1
HS_FLAG_DOTALL = 2
HS_FLAG_MULTILINE = 4
HS_FLAG_SINGLEMATCH = 8


class HyperscannerResult(ctypes.Structure):
    """Information about a regex result used to buffer matches from Intel Hyperscan before callbacks.

    C implementation located in pyhypergrep/common/shared/c/hyperscanner.c.

    Fields:
        id: The index of the pattern that matched the line.
        line_number: The index of the line matched in the file.
        line: Contents of the line that was matched.
    """

    _fields_ = [
        ('id', ctypes.c_uint),
        ('line_number', ctypes.c_ulonglong),
        ('line', ctypes.c_char_p),
    ]


# C function type used by hyperscanner to send line match batches back to python.
# Must be declared after struct class for proper pointer declaration.
HYPERSCANNER_CALLBACK_TYPE = ctypes.CFUNCTYPE(
    None,
    ctypes.POINTER(HyperscannerResult),
    ctypes.c_int,
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


def hyperscan(
        path: str,
        patterns: List[str],
        callback: Callable,
        buffer_size: int = 65535,
        buffer_count: int = 32,
        flags: List[int] = (),
) -> int:
    """Read a text file for regex patterns using Intel Hyperscan.

    Supports GZIP, ZSTD, and Plain Text files.

    Args:
        path: Location of the file to be read by hyperscan.
        patterns: Regex patterns in text format used to match lines.
        callback: Where every regex hit (line index, pattern id, and byte string) are sent.
            Must match HYPERSCANNER_CALLBACK_TYPE.
        buffer_size: How large of a buffer to use while reading in chars. Reads up to first newline or len - 1.
        buffer_count: How many line matches to buffer before calling callback.
            Reduces overhead of C callback calls, at cost of delaying python processing.
            Basic guidelines:
                Multithreading + millions of matches = increase limit.
                Multiprocessing or few matches = decrease limit or leave as is.
        flags: Flags to set on each pattern in order to match. i.e. HS_FLAG_DOTALL
            Flags must use bitwise OR operator to combine flags. e.g. HS_FLAG_DOTALL | HS_FLAG_SINGLEMATCH = 10
            Defaults to: HS_FLAG_DOTALL | HS_FLAG_MULTILINE | HS_FLAG_SINGLEMATCH

    Returns:
        Response code received from the C backend if there was a failure, 0 otherwise.
    """
    if not flags:
        # Set the default flags for most common usage if none were provided.
        # Hyperscan flags: https://intel.github.io/hyperscan/dev-reference/api_files.html
        # HS_FLAG_DOTALL for performance.
        # HS_FLAG_MULTILINE to match ^ and $ against newlines.
        # HS_FLAG_SINGLEMATCH to stop after first callback for a pattern.
        flags = [HS_FLAG_DOTALL | HS_FLAG_MULTILINE | HS_FLAG_SINGLEMATCH for _ in patterns]
    if len(flags) != len(patterns):
        raise ValueError(f'Found {len(flags)} flags, expecting {len(patterns)}. Hyperscan flags must be provided for each regex to compile the database.')

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
    flags_array = (ctypes.c_uint * (len(flags)))()
    flags_array[:] = [ctypes.c_uint(flag) for flag in flags]

    # Cache ZSTD/Hyperscan libraries first to provide hyperscanner lib fallback to static builds.
    # These will only be used if the OS does not have the libraries installed already.
    _get_zstd_lib()
    _get_hyperscan_lib()
    # Load and keep reference to the hyperscanner library to allow calling the functions.
    hyperscanner_lib = _get_hyperscanner_lib()

    callback = HYPERSCANNER_CALLBACK_TYPE(callback)
    ret_code = hyperscanner_lib.hyperscan(
        path.encode(),
        pattern_array,
        flags_array,
        len(pattern_array),
        callback,
        buffer_size,
        buffer_count,
    )
    return ret_code
