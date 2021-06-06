#! /usr/bin/env python

"""High performance python grep using Intel Hyperscan."""

import argparse
import ctypes
import multiprocessing
import os
import sys

from multiprocessing.pool import ThreadPool
from textwrap import dedent
from typing import Any
from typing import Generator
from typing import Iterable
from typing import List
from typing import Tuple
from typing import Union

from pyhypergrep.common import hyper_utils


def _grep_with_index(index: int, args: Iterable) -> Tuple[int, Any]:
    """Wrapper to run grep and return with an index representing the job ID."""
    try:
        result = grep(*args)
    except Exception as error:  # pylint: disable=broad-except
        result = error
    return index, result


def grep(file: str, pattern: str, with_index: bool) -> List[Union[str, Tuple[int, str]]]:
    """Search a file for a regex pattern.

    Args:
        file: Path to a file on the local filesystem.
        pattern: Regex pattern compatible with Intel Hyperscan.
        with_index: Whether to return the line indexes with the lines.

    Returns:
        List of strings, or list of tuples with the line index, matching the regex pattern.

    Raises:
        FileNotFoundError if the file does not exist.
        ValueError if the file is a directory.
    """
    lines = []

    def _c_callback(line_index: int, unused_match_id: int, line_ptr: ctypes.c_char_p) -> None:
        """Called by the C library everytime it finds a matching line."""
        line = line_ptr.decode(errors='ignore').rstrip()
        if with_index:
            lines.append((line_index + 1, line))
        else:
            lines.append(line)

    # Exception messages taken directly from "grep" error messages.
    if not os.path.exists(file):
        raise FileNotFoundError('No such file or directory')
    if os.path.isdir(file):
        raise ValueError('is a directory ')
    hyper_utils.hyperscan(file, [pattern], _c_callback)
    return lines


def print_results(
        results: list,
        file_name: str,
        with_file_name: bool = False,
        with_line_number: bool = False,
) -> None:
    """Print the full results to the screen based on user requested formatting.

    Args:
        results: Results of hyperscan processing.
        file_name: Path where the results were found.
        with_file_name: Whether to display the file name as a prefix.
        with_line_number: Whether to display the line number of each match as a prefix.
    """
    # Performing multiple if/then/else statement in a loop can be performance intensive.
    # Instead of performing one loop that performs the checks every time, perform the checks once, then loop.
    if with_file_name:
        if with_line_number:
            for line in results:
                print(f'{file_name}:{line[0]}:{line[1]}')
        else:
            for line in results:
                print(f'{file_name}:{line}')
    else:
        if with_line_number:
            for line in results:
                print(f'{line[0]}:{line[1]}')
        else:
            for line in results:
                print(line)


def read_stdin() -> Generator[str, None, None]:
    """Read from the system's standard input, such as pipes from other commands.

    This function is blocking until at least one line is read.

    Yields:
        Input from stdin with the line ending removed.
    """
    while True:
        line = sys.stdin.readline().strip()
        if not line:
            break
        yield line


def parse_args() -> argparse.Namespace:
    """Parse the args for the hyperscanner command.

    Returns:
        Processed args from CLI input.
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        # Do not add the default help, add it manually. Grep uses -h as a standard arg.
        add_help=False,
        description=dedent('''\
            Fast, multi-threaded, grep (Global Regular Expression Print).

            Intel Hyperscan based regex processor. Provides the following benefits over standard implementations:
                1. Extremely fast regex pattern matching, often faster than standard PCRE.
                2. Bypasses Python parallel processing limitations by reading files outside the global lock.
                3. Prevents the need to subprocess, a common design in Python based regex commands.
                    a. Reduces memory usage.
                    b. Reduces CPU usage.

            Differences from standard "grep" derivatives:
                1. Does not pass along arguments to a "grep" subprocess. Only allows arguments declared in this command.
                2. Does not support all regex constructs, but supports most common.
                    Example: No negative lookaheads
                    More details: https://intel.github.io/hyperscan/dev-reference/compilation.html#unsupported-constructs

            Examples:
                Pass file parameters from the command line, matching standard "grep":
                    $ hyperscanner <regex> <file(s)>
                Pass file parameters from stdin, usually piped from "find" or similar command:
                    $ find <args> | hyperscanner <regex>''')
    )
    # NOTE: Avoid adding any arguments that are reserved by "grep".
    # Other "grep" commands subprocess grep and pass through the args for maximum compatibility.
    # This command does not subprocess "grep" to maximum performance and resource usage.
    # All arguments that needs parity with "grep" must be declared here.
    # Arguments reserved by "grep":
    parser.add_argument('pattern', nargs=1,
                        help='Regex pattern to use.')
    parser.add_argument('files', nargs='*',
                        help='Files to scan.')
    filename_group = parser.add_mutually_exclusive_group()
    # Default to Nones in order to tell if user explicitly requested value, instead of default of False.
    filename_group.add_argument('-H', '--with-filename', action='store_true', default=None,
                                help='Print the file name for each match. This is the default when there is more than one file to search.')
    filename_group.add_argument('-h', '--no-filename', action='store_true', default=None,
                                help='Suppress the prefixing of file names on output. This is the default when there is only one file to search.')
    parser.add_argument('-n', '--line-number', action='store_true',
                        help='Prefix each line of output with the 1-based line number within its input file.')
    parser.add_argument('-c', '--count', action='store_true',
                        help='Suppress normal output; instead print a count of matching lines for each input file.')
    # Arguments not reserved by "grep" (unique to this command):
    parser.add_argument('-t', '--total', action='store_true',
                        help='Suppress normal output; instead print a count of matching lines across all input files.')
    parser.add_argument('--no-order', dest='ordered', action='store_false',
                        help='Print results as files finish, instead of waiting for previous files to complete.')
    parser.add_argument('--no-sort', dest='sort_files', action='store_false',
                        help='Keep original file order instead of naturally sorting.')
    # Add help manually, using only --help. Grep uses -h as a standard arg.
    parser.add_argument('--help', action='help', default=argparse.SUPPRESS,
                        help='show this help message and exit')
    parser.set_defaults(parser=parser)
    args = parser.parse_args()
    return args


def main() -> None:
    """Primary logic for hyperscanner command."""
    args = parse_args()
    files = args.files or list(read_stdin())
    if args.sort_files:
        files = sorted(files)
    if not files:
        print(args.parser.usage)
        raise SystemExit()

    # Default to show filename, and then check for user manual overrides, or single file override.
    with_filename = True
    if args.no_filename is not None:
        with_filename = False
    elif args.with_filename is not None:
        with_filename = True
    elif len(files) == 1:
        with_filename = False

    pattern = args.pattern[0]
    pending = {}
    total = 0
    next_index = 0

    def _on_grep_finish(result: Tuple[int, List[Union[str, Tuple[int, str]]]]) -> None:
        """Callback to parallel processing pool to track and print completed requests."""
        nonlocal total
        nonlocal next_index

        grep_index, grep_result = result
        if args.ordered and grep_index != next_index:
            pending[grep_index] = grep_result
            return

        file_name = files[grep_index]
        if isinstance(grep_result, Exception):
            # Error message style taken from "grep" output format.
            print(f'hyperscanner: {file_name}: {grep_result}')
            return
        if args.total:
            total += len(grep_result)
        elif args.count:
            print(f'{file_name}:{len(grep_result)}')
        else:
            print_results(
                grep_result,
                file_name,
                with_file_name=with_filename,
                with_line_number=args.line_number,
            )
        next_index += 1
        if next_index in pending:
            _on_grep_finish((next_index, pending.pop(next_index)))

    with ThreadPool(processes=max(multiprocessing.cpu_count() - 1, 1)) as pool:
        jobs = []
        for index, file in enumerate(files):
            jobs.append(pool.apply_async(_grep_with_index, (index, (file, pattern, args.line_number)), callback=_on_grep_finish))
        for job in jobs:
            job.get()
    pool.close()

    if args.total:
        print(total)


if __name__ == '__main__':
    main()
