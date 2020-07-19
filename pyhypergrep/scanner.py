"""Simple Intel Hyperscan file scanner."""

import argparse
import ctypes

from pyhypergrep.common import hyper_utils


def on_match(line_index: int, match_id: int, line_ptr: ctypes.c_char_p) -> None:
    """Callback for C library to send results.

    Args:
        line_index: Position of the line in a file.
        match_id: The match group/regex that this data was matched to.
        line_ptr: C pointer to bytes that can be decoded into text.
    """
    line = line_ptr.decode(errors='ignore')
    print(f'{line_index}:{line.rstrip()}')


def parse_args() -> argparse.Namespace:
    """Parse user arguments.

    Returns:
        Namespace with all the user arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('pattern', help='Regular expression to use.')
    parser.add_argument('file', help='File to process. May be uncompressed or gzip compressed.')
    args = parser.parse_args()
    return args


def main() -> None:
    """Primary function to scan text file."""
    args = parse_args()

    hyper_utils.hyperscan(args.file, [args.pattern], on_match)


if __name__ == '__main__':
    main()
