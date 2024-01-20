#! /usr/bin/env python3

"""High performance python grep using Intel Hyperscan."""

import argparse
import multiprocessing
import os
import re
import sys
from multiprocessing.pool import ThreadPool
from textwrap import dedent
from typing import Any
from typing import Generator
from typing import Iterable

from hypergrep.common import hyper_utils


def _grep_with_index(index: int, args: Iterable) -> tuple[int, Any]:
    """Wrapper to run grep and return with an index representing the job ID."""
    try:
        result = grep(*args)
    except Exception as error:  # pylint: disable=broad-except
        result = error
    return index, result


def get_argparse_files(args: argparse.Namespace) -> list[str]:
    """Pull all files requested by the user from "grep" argparse arguments.

    Args:
        args: Processed argparse namespace.

    Returns:
        Simplified list of all valid files from user arguments.
    """
    # GNU grep allows specifying a pattern as a positional, or optional multiple times.
    # NOTE: If at least 1 optional is used for a pattern (-e-f), then use the pattern positional as a file.
    all_files = []
    if (args.pattern_files or args.patterns) and args.pattern:
        all_files.append(args.pattern)
    if args.files:
        all_files.extend(args.files)
    return all_files


def get_argparse_patterns(args: argparse.Namespace) -> list[str]:
    """Pull all patterns requested by the user from "grep" argparse arguments.

    Args:
        args: Processed argparse namespace.

    Returns:
        Simplified list of all valid regex patterns from user arguments.

    Raises:
        ValueError if any of the regexes are invalid.
    """
    # GNU grep allows specifying a pattern as a positional, or optional multiple times.
    # NOTE: If at least 1 optional is used for a pattern (-e/-f), then use the pattern positional as a file.
    all_patterns = []
    if args.patterns:
        all_patterns.extend(args.patterns)
    elif not args.pattern_files and args.pattern:
        all_patterns.append(args.pattern)
    if args.pattern_files:
        for file_name in args.pattern_files:
            with open(file_name, "rt", encoding="utf-8") as pattern_file:
                all_patterns.extend(pattern.rstrip("\n") for pattern in pattern_file.readlines())

    # Perform a basic regex compilation test before Hyperscan is started.
    # This does not guarantee 100% compatibility, but reduces the need for Hyperscan to validate common errors.
    for pattern in all_patterns:
        try:
            re.compile(pattern)
        except Exception as error:
            raise ValueError(f"hyperscanner: invalid regex: {error}") from error
    # Perform final validation using Hyperscan. Some regex constructs are PCRE compatible, but not Hyperscan compatible.
    # Unfortunately Hyperscan does not return the exact reason, just a generic non-zero compilation failure return code.
    if hyper_utils.check_hyperscan_compatibility(all_patterns):
        raise ValueError(
            "hyperscanner: incompatible regex: for more information visit https://intel.github.io/hyperscan/dev-reference/compilation.html#unsupported-constructs"
        )
    return all_patterns


def grep(
    file: str,
    patterns: list[str],
    ignore_case: bool,
    count_only: bool,
    only_matching: bool,
    no_messages: bool,
) -> int | list[tuple[int, str]]:
    """Search a file for a regex pattern.

    Args:
        file: Path to a file on the local filesystem.
        patterns: Regex patterns compatible with Intel Hyperscan.
        ignore_case: Perform case-insensitive matching.
        count_only: Whether to count the matches, instead of decode the byte lines and store them.
        only_matching: Save only the matched (non-empty) parts of a matching line, with each part on a separate line.
        no_messages: Suppress error messages about nonexistent or unreadable files.

    Returns:
        Line count, or list of tuples with the line index and matching line.

    Raises:
        FileNotFoundError if the file does not exist.
        ValueError if the file is a directory.
    """
    compiled_patterns = [re.compile(pattern) for pattern in patterns]
    lines = [] if not count_only else 0

    def _c_callback(matches: list, count: int) -> None:
        """Called by the C library everytime it finds a matching line."""
        nonlocal lines
        if count_only:
            lines += count
        else:
            if only_matching:
                # "Only matching" grep behavior converts every line into every match group per line.
                for index in range(count):
                    match = matches[index]
                    line = match.line.decode(errors="ignore")
                    # NOTE: Do not use findall, only finditer provides the correct results.
                    for partial in compiled_patterns[match.id].finditer(line):
                        lines.append((match.line_number + 1, f"{partial.group()}\n"))
            else:
                for index in range(count):
                    match = matches[index]
                    line = match.line.decode(errors="ignore")
                    lines.append((match.line_number + 1, line))

    valid = True
    # Exception messages taken directly from "grep" error messages.
    # Silent behavior also taken from "grep" to not raise or print a message if path is invalid.
    if not os.path.exists(file):
        valid = False
        if not no_messages:
            raise FileNotFoundError("No such file or directory")
    if os.path.isdir(file):
        valid = False
        if not no_messages:
            raise ValueError("is a directory")

    if valid:
        # Always use hyperscan function defaults, but add caseless if user requested.
        flags = hyper_utils.HS_FLAG_DOTALL | hyper_utils.HS_FLAG_MULTILINE | hyper_utils.HS_FLAG_SINGLEMATCH
        if ignore_case:
            flags |= hyper_utils.HS_FLAG_CASELESS
        hyper_utils.hyperscan(file, patterns, _c_callback, flags=[flags for _ in patterns])
    return lines


def parallel_grep(  # This cannot be shortened due to parallel pool usage. pylint: disable=too-many-arguments,too-many-locals
    files: list,
    patterns: list[str],
    ignore_case: bool = False,
    ordered_results: bool = True,
    count_results: bool = False,
    total_results: bool = False,
    with_file_name: bool = False,
    with_line_number: bool = False,
    use_multithreading: bool = True,
    only_matching: bool = False,
    no_messages: bool = False,
) -> None:
    """Search files for a regex pattern and print the results based on user requested formatting.

    Args:
        files: All files to scan for pattern.
        patterns: Regex patterns compatible with Intel Hyperscan.
        ignore_case: Perform case-insensitive matching.
        ordered_results: Wait for previous files to complete before printing results.
        count_results: Print a count of matching lines for each input file, instead of printing matches.
        total_results: Print a cumulative total across all files of matching lines, instead of printing matches.
        with_file_name: Whether to display the file name as a prefix.
        with_line_number: Whether to display the line number of each match as a prefix.
        use_multithreading: Whether to use multithreading pool instead of multiprocessing.
        only_matching: Save only the matched (non-empty) parts of a matching line, with each part on a separate line.
        no_messages: Suppress error messages about nonexistent or unreadable files.
    """
    pending = {}
    total = 0
    next_index = 0

    def _on_grep_finish(result: tuple[int, list[str | tuple[int, str]]]) -> None:
        """Callback to parallel processing pool to track and print completed requests."""
        nonlocal total
        nonlocal next_index

        grep_index, grep_result = result
        if ordered_results and grep_index != next_index:
            pending[grep_index] = grep_result
            return
        file_name = files[grep_index]
        if isinstance(grep_result, Exception):
            # Error message style taken from "grep" output format.
            print(f"hyperscanner: {file_name}: {grep_result}")
            return
        if total_results:
            total += grep_result
        elif count_results:
            if with_file_name:
                print(f"{file_name}:{grep_result}")
            else:
                print(f"{grep_result}")
        else:
            try:
                print_results(
                    grep_result,
                    file_name,
                    with_file_name=with_file_name,
                    with_line_number=with_line_number,
                )
            except BrokenPipeError as error:
                # NOTE: Piping output to additional commands such as head may close the output file.
                # This is unavoidable, and the only thing that can be done is catch, and exit.
                raise SystemExit(1) from error
        next_index += 1
        if next_index in pending:
            _on_grep_finish((next_index, pending.pop(next_index)))

    workers = min(max(multiprocessing.cpu_count() - 1, 1), len(files))
    with ThreadPool(processes=workers) if use_multithreading else multiprocessing.Pool(processes=workers) as pool:
        jobs = []
        for index, file in enumerate(files):
            args = (file, patterns, ignore_case, count_results or total_results, only_matching, no_messages)
            jobs.append(pool.apply_async(_grep_with_index, (index, args), callback=_on_grep_finish))
        for job in jobs:
            job.get()

    if total_results:
        print(total)


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
                print(f"{file_name}:{line[0]}:{line[1]}", end="")
        else:
            for line in results:
                print(f"{file_name}:{line[1]}", end="")
    else:
        if with_line_number:
            for line in results:
                print(f"{line[0]}:{line[1]}", end="")
        else:
            for line in results:
                print(line[1], end="")


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


def to_basic_regular_expressions(patterns: list[str]) -> list[str]:
    """Convert regexes into POSIX style Basic Regular Expressions (BRE).

    Args:
        patterns: Extended Regular Expression (ERE) or Perl Compatible Regular Expression (PCRE) patterns.

    Returns:
        ERE/PCREs with BRE non-regex special characters escaped to act as literals.
    """
    basic_patterns = []
    for pattern in patterns:
        # BREs provide compatibility back to the original Unix "grep" by:
        #   1. Treating some regex characters compatible with ERE/PCRE as literals.
        #   2. Turning escaped regex characters into regular ERE/PCRE compatible regex characters.
        # This requires a 3 step swap to prevent swapping all characters in one direction:
        #   1. Flag all the BRE characters that are not already preceded by escapes to be escaped.
        #   2. Swap all previously escaped BRE characters with normal regex characters.
        #   3. Swap the flagged BRE characters with escaped characters.
        # This is the default pattern behavior of "grep". See "man grep" for more details.
        # ERE/PCRE special regex characters: .*^$+?()[]{}|
        # BRE regex characters treated as literals: +?(){}|
        basic_pattern = re.sub(r"(?<!\\)([+?(){}|])", lambda match: f"HYPERSCANNERSWAPFLAG{match.group(0)}", pattern)
        basic_pattern = re.sub(r"(\\[+?(){}|])", lambda match: match.group(0)[-1], basic_pattern)
        basic_pattern = re.sub(
            r"HYPERSCANNERSWAPFLAG([+?(){}|])", lambda match: f"\\{match.group(0)[-1]}", basic_pattern
        )
        basic_patterns.append(basic_pattern)
        # Perform another validation pass after a downgrade of the pattern to BRE to ensure it is still compatible.
        try:
            re.compile(basic_pattern)
        except Exception as error:
            raise ValueError(f"hyperscanner: invalid regex: {error}") from error
    return basic_patterns


def to_gnu_regular_expressions(patterns: list[str]) -> list[str]:
    """Convert regexes into GNU style regexes.

    This should not be used if the original regex is PCRE. PCRE expects patterns as is, without swaps.

    Args:
        patterns: Basic/Extended Regular Expression (BRE/ERE) patterns.

    Returns:
        BRE/EREs with GNU special patterns swapped for PCRE compatibility..
    """
    gnu_patterns = []
    for pattern in patterns:
        # GNU grep provides an extra set of characters that behave like PCRE, but with different declarations.
        # This is the default pattern behavior of "grep". See "man grep" for more details.
        # GNU regex characters to be swapped for ERE/PCRE patterns:
        # \< == \b
        # \> == \b
        basic_pattern = re.sub(r"(?<!\\)(\\[<>])", lambda match: "\\b", pattern)
        gnu_patterns.append(basic_pattern)
    return gnu_patterns


def parse_args(args: list = None) -> argparse.Namespace:
    """Parse the args for the hyperscanner command.

    Returns:
        Processed args from CLI input.
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        # Do not add the default help, add it manually. Grep uses -h as a standard arg.
        add_help=False,
        description=dedent(
            """\
            Fast, multi-threaded, grep (Global Regular Expression Print).

            Intel Hyperscan based regex processor. Provides the following benefits over standard implementations:
                1. Extremely fast multi-pattern regex matching.
                2. Bypasses Python multithreading limitations by reading files outside the global lock.
                3. Prevents the need to subprocess.
                    a. Reduces memory usage.
                    b. Reduces CPU usage.
                    c. Reduces process chain. 1 process, instead of python > zgrep > zcat > grep.

            Differences from standard "grep" derivatives:
                1. Does not pass along arguments to a "grep" subprocess. Only allows arguments declared in this command.
                2. Does not support all regex constructs, but supports most common.
                    Example: No negative lookaheads
                    More details: https://intel.github.io/hyperscan/dev-reference/compilation.html#unsupported-constructs

            Examples:
                Pass file parameters from the command line, matching standard "grep":
                    $ hyperscanner <regex> <file(s)>
                Pass file parameters from stdin, usually piped from "find" or similar command:
                    $ find <args> | hyperscanner <regex>"""
        ),
    )
    # NOTE: Avoid adding any arguments that are reserved by "grep".
    # Other "grep" commands subprocess grep and pass through the args for maximum compatibility.
    # This command does not subprocess "grep" to maximum performance and resource usage.
    # All arguments that needs parity with "grep" must be declared here.

    # Arguments reserved by "grep". Argparse groups match "grep" help output organization:
    parser.add_argument("pattern", nargs="?", help="Regex pattern to use.")
    parser.add_argument("files", nargs="*", help="Files to scan.")

    generic_args = parser.add_argument_group("Generic Program Information")
    # Add help manually, using only --help. Grep uses -h as a standard arg.
    generic_args.add_argument(
        "--help", action="help", default=argparse.SUPPRESS, help="show this help message and exit"
    )

    pattern_args = parser.add_argument_group("Pattern Syntax")
    regexp_group = pattern_args.add_mutually_exclusive_group()
    regexp_group.set_defaults(regexp="bre")
    regexp_group.add_argument(
        "-E",
        "--extended-regexp",
        dest="regexp",
        action="store_const",
        const="ere",
        help="Interpret PATTERNS as extended regular expressions (EREs).",
    )
    regexp_group.add_argument(
        "-G",
        "--basic-regexp",
        dest="regexp",
        action="store_const",
        const="bre",
        help='Interpret PATTERNS as basic regular expressions (See "man grep" for more details). This is the default.',
    )
    regexp_group.add_argument(
        "-P",
        "--perl-regexp",
        dest="regexp",
        action="store_const",
        const="pcre",
        help="Interpret PATTERNS as Perl-compatible regular expressions (PCREs).",
    )

    matching_args = parser.add_argument_group("Matching Control")
    matching_args.add_argument(
        "-e",
        "--regexp",
        action="append",
        dest="patterns",
        metavar="pattern",
        help="Use PATTERNS as the patterns. If this option is used multiple times or is combined with the -f (--file) option, search for all patterns given.",
    )
    matching_args.add_argument(
        "-f",
        "--file",
        action="append",
        dest="pattern_files",
        metavar="file",
        help="Obtain patterns from FILE, one per line. If this option is used multiple times or is combined with the -e (--regexp) option, search for all patterns given. The empty file contains zero patterns, and therefore matches nothing.",
    )
    matching_args.add_argument(
        "-i",
        "--ignore-case",
        action="store_true",
        help="Perform case insensitive matching.  By default, grep is case sensitive.",
    )

    output_args = parser.add_argument_group("General Output Control")
    output_args.add_argument(
        "-c",
        "--count",
        action="store_true",
        help="Suppress normal output; instead print a count of matching lines for each input file.",
    )
    output_args.add_argument(
        "-o",
        "--only-matching",
        action="store_true",
        help="Print only the matched (non-empty) parts of a matching line, with each such part on a separate output line.",
    )
    output_args.add_argument(
        "-s",
        "--no-messages",
        action="store_true",
        help="Suppress error messages about nonexistent or unreadable files.",
    )

    prefix_args = parser.add_argument_group("Output Line Prefix Control")
    # Default to Nones in order to tell if user explicitly requested value, instead of default of False.
    filename_group = prefix_args.add_mutually_exclusive_group()
    filename_group.add_argument(
        "-H",
        "--with-filename",
        action="store_true",
        default=None,
        help="Print the file name for each match. This is the default when there is more than one file to search.",
    )
    filename_group.add_argument(
        "-h",
        "--no-filename",
        action="store_true",
        default=None,
        help="Suppress the prefixing of file names on output. This is the default when there is only one file to search.",
    )
    prefix_args.add_argument(
        "-n",
        "--line-number",
        action="store_true",
        help="Prefix each line of output with the 1-based line number within its input file.",
    )

    selection_args = parser.add_argument_group("File and Directory Selection")
    selection_args.add_argument(
        "-a",
        "--text",
        action="store_true",
        help="Process a binary file as if it were text; this is equivalent to the --binary-files=text option. "
        "(Dummy option for cross-compatibility with grep. Files are always processed as binary.)",
    )

    # Arguments not reserved by "grep" (unique to this command):
    hyper_args = parser.add_argument_group("Unique arguments to hyperscanner")
    hyper_args.add_argument(
        "-t",
        "--total",
        action="store_true",
        help="Suppress normal output; instead print a count of matching lines across all input files.",
    )
    hyper_args.add_argument(
        "--no-gnu",
        dest="gnu_regexp",
        action="store_false",
        help="Disable conversions that modify the regex for GNU grep compatibility. Only performed with BRE and ERE patterns. Example: \\< swapped with \\b",
    )
    hyper_args.add_argument(
        "--no-order",
        dest="ordered",
        action="store_false",
        help="Print results as files finish, instead of waiting for previous files to complete.",
    )
    hyper_args.add_argument(
        "--no-sort",
        dest="sort_files",
        action="store_false",
        help="Keep original file order instead of naturally sorting.",
    )
    hyper_args.add_argument(
        "--mp",
        action="store_false",
        dest="use_multithreading",
        help="Use multiprocessing pool instead of multithreading. May help print extremely large results faster (1M+).",
    )

    # Attach the parser to allow manually referencing its help output printer.
    parser.set_defaults(parser=parser)
    args = parser.parse_intermixed_args(args=args)
    return args


def main() -> None:
    """Primary logic for hyperscanner command."""
    args = parse_args()
    try:
        patterns = get_argparse_patterns(args)
    except ValueError as error:
        print(error)
        raise SystemExit(2) from error  # Match grep behavior of exiting with a 2 (Misuse of shell builtins).

    if not patterns:
        args.parser.print_usage()
        raise SystemExit(2)  # Match grep behavior of exiting with a 2 (Misuse of shell builtins).
    if args.regexp not in ("ere", "pcre"):
        try:
            patterns = to_basic_regular_expressions(patterns)
        except ValueError as error:
            print(error)
            raise SystemExit(2) from error  # Match grep behavior of exiting with a 2 (Misuse of shell builtins).
    if args.gnu_regexp and args.regexp != "pcre":
        # GNU patterns are compatible with ERE, but not PCRE. PCRE expects full modern syntax.
        patterns = to_gnu_regular_expressions(patterns)

    files = get_argparse_files(args) or list(read_stdin())
    if args.sort_files:
        files = sorted(files)
    if not files:
        args.parser.print_usage()
        raise SystemExit(2)  # Match grep behavior of exiting with a 2 (Misuse of shell builtins).

    # Default to show filename, and then check for user manual overrides, or single file override.
    with_filename = True
    if args.no_filename is not None:
        with_filename = False
    elif args.with_filename is not None:
        with_filename = True
    elif len(files) == 1:
        with_filename = False

    parallel_grep(
        files=files,
        patterns=patterns,
        ignore_case=args.ignore_case,
        ordered_results=args.ordered,
        count_results=args.count,
        total_results=args.total,
        with_file_name=with_filename,
        with_line_number=args.line_number,
        use_multithreading=args.use_multithreading,
        only_matching=args.only_matching,
        no_messages=args.no_messages,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as user_interrupt:
        raise SystemExit(130) from user_interrupt  # Exit with 130 for "script exited with ctrl+c".
