"""Utilities for scanning text files with Intel Hyperscan"""

import ctypes
import os
import threading

from typing import Callable
from typing import List
from typing import Tuple

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
    # Cache ZSTD/Hyperscan libraries first to provide hyperscanner lib fallback to static builds.
    # These will only be used if the OS does not have the libraries installed already.
    _get_zstd_lib()
    _get_hyperscan_lib()
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
        lib_path = os.path.join(parent, 'shared', 'libzstd.so.1.5.0')
        _ZSTD_LIB = ctypes.cdll.LoadLibrary(lib_path)
    return _ZSTD_LIB


def check_hyperscan_compatibility(
        patterns: list,
        flags: List[int] = (),
) -> int:
    """Helper to test regex pattern compilation in Intel Hyperscan without scanning a file.

    Examples of bad patterns tested by Hyperscan can be found in their code at: unit/hyperscan/bad_patterns.cpp

    Args:
        patterns: Regex patterns in text format used to match lines.
        flags: Flags to set on each pattern in order to match. i.e. HS_FLAG_DOTALL
            Flags must use bitwise OR operator to combine flags. e.g. HS_FLAG_DOTALL | HS_FLAG_SINGLEMATCH = 10
            Defaults to: HS_FLAG_DOTALL | HS_FLAG_MULTILINE | HS_FLAG_SINGLEMATCH

    Returns:
        ret_code: The response code received from the C backend if there was a failure, 0 otherwise.
    """
    pattern_array, flags_array, ids_array = prepare_hyperscan_patterns(patterns, flags=flags)
    hyperscanner_lib = _get_hyperscanner_lib()
    ret_code = hyperscanner_lib.check_patterns(
        pattern_array,
        flags_array,
        ids_array,
        len(pattern_array),
    )
    return ret_code


def hyperscan(
        path: str,
        patterns: List[str],
        callback: Callable,
        flags: List[int] = (),
        ids: List[int] = (),
        buffer_size: int = 65535,
        buffer_count: int = 32,
) -> int:
    """Read a text file for regex patterns using Intel Hyperscan.

    Supports GZIP, ZSTD, and Plain Text files.

    Args:
        path: Location of the file to be read by hyperscan.
        patterns: Regex patterns in text format used to match lines.
        callback: Where every regex hit (line index, pattern id, and byte string) are sent.
            Must match HYPERSCANNER_CALLBACK_TYPE.
        flags: Flags to set on each pattern in order to match. i.e. HS_FLAG_DOTALL
            Flags must use bitwise OR operator to combine flags. e.g. HS_FLAG_DOTALL | HS_FLAG_SINGLEMATCH = 10
            Defaults to: HS_FLAG_DOTALL | HS_FLAG_MULTILINE | HS_FLAG_SINGLEMATCH
        ids: IDs to apply to each pattern to group related patterns and prevent separate callbacks.
            Defaults to: All patterns share the same ID; multiple callbacks for the same line are not received.
        buffer_size: How large of a buffer to use while reading in chars. Reads up to first newline or len - 1.
        buffer_count: How many line matches to buffer before calling callback.
            Reduces overhead of C callback calls, at cost of delaying python processing.
            Basic guidelines:
                Multithreading + millions of matches = increase limit.
                Multiprocessing or few matches = decrease limit or leave as is.

    Returns:
        Response code received from the C backend if there was a failure, 0 otherwise.
    """
    pattern_array, flags_array, ids_array = prepare_hyperscan_patterns(patterns, flags=flags, ids=ids)

    # Wrap the callback in the ctype to allow passing to C functions.
    callback = HYPERSCANNER_CALLBACK_TYPE(callback)
    hyperscanner_lib = _get_hyperscanner_lib()
    ret_code = 0

    # NOTE: Do not remove this wrapper or change thread from daemon to ensure that Python receives signals.
    def _wrapper() -> None:
        """Wrapper to allow running the CDLL call as non-blocking and allow Python to intercept signals."""
        nonlocal ret_code
        ret_code = hyperscanner_lib.hyperscan(
            path.encode(),
            pattern_array,
            flags_array,
            ids_array,
            len(pattern_array),
            callback,
            buffer_size,
            buffer_count,
        )
    hyperscan_thread = threading.Thread(target=_wrapper, daemon=True)
    hyperscan_thread.start()
    try:
        # Hard cap the thread at 1 hour in case anything goes wrong.
        hyperscan_thread.join(timeout=3600)
    except KeyboardInterrupt:
        ret_code = 130
    return ret_code


def hypergrep(
        file: str,
        patterns: List[str],
) -> Tuple[int, List[str]]:
    """Basic reusable grep like function using Intel Hyperscan.

    Contrary to the "grep" in the name, it returns the lines instead of printing them. Useful for testing
    basic functionality on a system, or simple use cases.

    Args:
        file: Path to a file on the local filesystem.
        patterns: Regex patterns compatible with Intel Hyperscan.

    Returns:
        Hyperscan return code, and matching lines.
    """
    lines = []

    def _c_callback(matches: List[HyperscannerResult], count: int) -> None:
        """Called by the C library everytime it finds a matching line."""
        nonlocal lines
        for index in range(count):
            match = matches[index]
            line = match.line.decode(errors='ignore')
            lines.append(line)

    return_code = hyperscan(file, patterns, _c_callback)
    return return_code, lines


def prepare_hyperscan_patterns(
        patterns: List[str],
        flags: List[int] = (),
        ids: List[int] = (),
) -> Tuple[ctypes.Array, ctypes.Array, ctypes.Array]:
    """Prepare python regexes and flags for use with Intel Hyperscan.

    Args:
        patterns: Regex patterns in text format used to match lines.
        flags: Flags to set on each pattern in order to match. i.e. HS_FLAG_DOTALL
            Flags must use bitwise OR operator to combine flags. e.g. HS_FLAG_DOTALL | HS_FLAG_SINGLEMATCH = 10
            Defaults to: HS_FLAG_DOTALL | HS_FLAG_MULTILINE | HS_FLAG_SINGLEMATCH
        ids: IDs to apply to each pattern to group related patterns and prevent separate callbacks.
            Defaults to: All patterns share the same ID; multiple callbacks for the same line are not received.

    Returns:
        C array of strings, and C array of ints, compatible as C lib function args.
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

    if not ids:
        # Set the default group IDs to 0 for the most common usage if none were provided (all patterns in 1 group).
        # This will ensure that searching will stop after the first match, and only 1 callback is received per line.
        ids = [0 for _ in patterns]
    if len(ids) != len(patterns):
        raise ValueError(f'Found {len(ids)} ids, expecting {len(patterns)}. Hyperscan ids must be provided for each regex to compile the database.')

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
    ids_array = (ctypes.c_uint * (len(ids)))()
    ids_array[:] = [ctypes.c_uint(id_num) for id_num in ids]
    return pattern_array, flags_array, ids_array
