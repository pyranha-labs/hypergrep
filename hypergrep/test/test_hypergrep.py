"""Test cases for the hypergrep module."""

import argparse
import builtins
import io
import os
import shlex
import sys
from typing import Any
from typing import Callable

import pytest

from hypergrep import hyperscanner
from hypergrep import utils


def _dummy_callback(matches: list, count: int) -> None:
    """Callback for C library to send results."""
    for index in range(count):
        match = matches[index]
        line = match.line.decode(errors="ignore")
        print(f"{match.line_number}:{line.rstrip()}")


DUMMY_FILE_1 = os.path.join(os.path.dirname(__file__), "greptest1.txt")
DUMMY_FILE_2 = os.path.join(os.path.dirname(__file__), "greptest2.txt")
FAKE_FILES = {
    "regex.txt": "filepattern1\nfilepattern2",
}
TEST_FILE = os.path.join(os.path.dirname(__file__), "dummyfile.txt")
TEST_CASES = {
    "argparse_namespace_comparator": {
        "matched": {
            "args": [
                argparse.Namespace(
                    files=["f1", "f2", "f3"],
                    pattern="p1",
                ),
                argparse.Namespace(
                    files=["f1", "f2", "f3"],
                    pattern="p1",
                ),
            ],
            "returns": None,
        },
        "mismatched": {
            "args": [
                argparse.Namespace(
                    files=["f1", "f2", "f3"],
                    pattern="p1",
                ),
                argparse.Namespace(
                    files=["f1", "f2"],
                    pattern="p2",
                ),
            ],
            "raises": AssertionError,
        },
    },
    "check_hyperscan_compatibility": {
        "PCRE and Hyperscan compatible": {
            "args": [["foobar"]],
            "returns": 0,
        },
        "PCRE compatible but Hyperscan incompatible": {
            # Negative lookbehind example taken from: unit/hyperscan/bad_patterns.cpp
            "args": [["(?<!foo)bar"]],
            "returns": 4,
        },
    },
    "get_argparse_files": {
        "leading pattern positional and file positionals": {
            "args": [
                hyperscanner.parse_args(shlex.split("pattern1 file1 file2 file3")),
            ],
            "returns": ["file1", "file2", "file3"],
        },
        "Leading pattern positional and pattern optional": {
            # See hyperscanner.get_argparse_files for explanation of why pattern1 is considered a file in this scenario.
            "args": [
                hyperscanner.parse_args(shlex.split("pattern1 -e pattern2 file1")),
            ],
            "returns": ["pattern1", "file1"],
        },
        "Leading pattern positional and pattern file optional": {
            # See hyperscanner.get_argparse_files for explanation of why pattern1 is considered a file in this scenario.
            "args": [
                hyperscanner.parse_args(shlex.split("pattern1 -f regex.txt file1")),
            ],
            "returns": ["pattern1", "file1"],
        },
        "Leading pattern positional, pattern optional, and pattern file optional": {
            # See hyperscanner.get_argparse_files for explanation of why pattern1 is considered a file in this scenario.
            "args": [
                hyperscanner.parse_args(shlex.split("pattern1 -e pattern2 -f regex.txt file1")),
            ],
            "returns": ["pattern1", "file1"],
        },
        "intermixed pattern positional, trailing file positionals, and pattern optionals": {
            # See hyperscanner.get_argparse_files for explanation of why pattern1 is considered a file in this scenario.
            "args": [
                hyperscanner.parse_args(shlex.split("-e pattern2 pattern1 -e pattern3 file1 file2")),
            ],
            "returns": ["pattern1", "file1", "file2"],
        },
        "pattern positional, intermixed file positionals, and pattern optionals": {
            # See hyperscanner.get_argparse_files for explanation of why pattern1 is considered a file in this scenario.
            "args": [
                hyperscanner.parse_args(shlex.split("pattern1 file1 -e pattern2 file2 -e pattern3 file3 f4")),
            ],
            "returns": ["pattern1", "file1", "file2", "file3", "f4"],
        },
    },
    "get_argparse_patterns": {
        "leading pattern positional and file positionals": {
            "args": [
                hyperscanner.parse_args(shlex.split("pattern1 file1 file2 file3")),
            ],
            "returns": ["pattern1"],
        },
        "Leading pattern positional and pattern optional": {
            # See hyperscanner.get_argparse_patterns for explanation of why pattern1 is not considered a pattern in this scenario.
            "args": [
                hyperscanner.parse_args(shlex.split("pattern1 -e pattern2 file1")),
            ],
            "returns": ["pattern2"],
        },
        "Leading pattern positional and pattern file optional": {
            # See hyperscanner.get_argparse_patterns for explanation of why pattern1 is not considered a pattern in this scenario.
            "args": [
                hyperscanner.parse_args(shlex.split("pattern1 -f regex.txt file1")),
            ],
            "returns": ["filepattern1", "filepattern2"],
        },
        "Leading pattern positional, pattern optional, and pattern file optional": {
            # See hyperscanner.get_argparse_patterns for explanation of why pattern1 is not considered a pattern in this scenario.
            "args": [
                hyperscanner.parse_args(shlex.split("pattern1 -e pattern2 -f regex.txt file1")),
            ],
            "returns": ["pattern2", "filepattern1", "filepattern2"],
        },
        "intermixed pattern positional, trailing file positionals, and pattern optionals": {
            # See hyperscanner.get_argparse_patterns for explanation of why pattern1 is not considered a pattern in this scenario.
            "args": [
                hyperscanner.parse_args(shlex.split("-e pattern2 pattern1 -e pattern3 file1 file2")),
            ],
            "returns": ["pattern2", "pattern3"],
        },
        "pattern positional, intermixed file positionals, and pattern optionals": {
            # See hyperscanner.get_argparse_patterns for explanation of why pattern1 is not considered a pattern in this scenario.
            "args": [
                hyperscanner.parse_args(shlex.split("pattern1 file1 -e pattern2 file2 -e pattern3 file3 f4")),
            ],
            "returns": ["pattern2", "pattern3"],
        },
    },
    "hyperscan": {
        "one pattern": {
            "args": [
                TEST_FILE,
                ["bar"],
                _dummy_callback,
            ],
            "returns": [
                "1:foobar",
                "2:barfoo",
            ],
        },
        "two patterns": {
            "args": [
                TEST_FILE,
                [
                    "bar",
                    "food",
                ],
                _dummy_callback,
            ],
            "returns": [
                "1:foobar",
                "2:barfoo",
                "3:food",
            ],
        },
    },
    "grep": {
        "one pattern, no index": {
            "args": [
                TEST_FILE,
                ["bar"],
                False,
                False,
                False,
                False,
            ],
            "returns": [
                (2, "foobar\n"),
                (3, "barfoo\n"),
            ],
        },
    },
    "parallel_grep": {
        "single file, with file name": {
            "args": [
                [DUMMY_FILE_1],
                ["foobar"],
            ],
            "kwargs": {
                "count_results": False,
                "total_results": False,
                "with_file_name": True,
                "with_line_number": False,
            },
            "returns": [
                "greptest1.txt:foobar",
            ],
        },
        "single file, with file name and line index": {
            "args": [
                [DUMMY_FILE_1],
                ["foobar"],
            ],
            "kwargs": {
                "count_results": False,
                "total_results": False,
                "with_file_name": True,
                "with_line_number": True,
            },
            "returns": [
                "greptest1.txt:3:foobar",
            ],
        },
        "single file, with file name and count": {
            "args": [
                [DUMMY_FILE_1],
                ["foo"],
            ],
            "kwargs": {
                "count_results": True,
                "total_results": False,
                "with_file_name": True,
                "with_line_number": False,
            },
            "returns": [
                "greptest1.txt:16",
            ],
        },
        "single file, with file name and total": {
            "args": [
                [DUMMY_FILE_1],
                ["foo"],
            ],
            "kwargs": {
                "count_results": False,
                "total_results": True,
                "with_file_name": True,
                "with_line_number": False,
            },
            "returns": [
                # It is expected for total to not show a file name, it is a total. This ensures expected behavior.
                "16",
            ],
        },
        "single file, no file name, with line index": {
            "args": [
                [DUMMY_FILE_1],
                ["foobar"],
            ],
            "kwargs": {
                "count_results": False,
                "total_results": False,
                "with_file_name": False,
                "with_line_number": True,
            },
            "returns": [
                "3:foobar",
            ],
        },
        "single file, no file name, with count": {
            "args": [
                [DUMMY_FILE_1],
                ["foo"],
            ],
            "kwargs": {
                "count_results": True,
                "total_results": False,
                "with_file_name": False,
                "with_line_number": False,
            },
            "returns": [
                "16",
            ],
        },
        "single file, no file name, with total": {
            "args": [
                [DUMMY_FILE_1],
                ["foo"],
            ],
            "kwargs": {
                "count_results": False,
                "total_results": True,
                "with_file_name": False,
                "with_line_number": False,
            },
            "returns": [
                "16",
            ],
        },
        "multi file, with file name": {
            "args": [
                [DUMMY_FILE_1, DUMMY_FILE_2],
                ["foobar"],
            ],
            "kwargs": {
                "count_results": False,
                "total_results": False,
                "with_file_name": True,
                "with_line_number": False,
            },
            "returns": [
                "greptest1.txt:foobar",
                "greptest2.txt:foobar",
            ],
        },
        "multi file, with file name and line index": {
            "args": [
                [DUMMY_FILE_1, DUMMY_FILE_2],
                ["foobar"],
            ],
            "kwargs": {
                "count_results": False,
                "total_results": False,
                "with_file_name": True,
                "with_line_number": True,
            },
            "returns": [
                "greptest1.txt:3:foobar",
                "greptest2.txt:3:foobar",
            ],
        },
        "multi file, with file name and count": {
            "args": [
                [DUMMY_FILE_1, DUMMY_FILE_2],
                ["foo"],
            ],
            "kwargs": {
                "count_results": True,
                "total_results": False,
                "with_file_name": True,
                "with_line_number": False,
            },
            "returns": [
                "greptest1.txt:16",
                "greptest2.txt:16",
            ],
        },
        "multi file, with file name and total": {
            "args": [
                [DUMMY_FILE_1, DUMMY_FILE_2],
                ["foo"],
            ],
            "kwargs": {
                "count_results": False,
                "total_results": True,
                "with_file_name": True,
                "with_line_number": False,
            },
            "returns": [
                # It is expected for total to not show a file name, it is a total. This ensures expected behavior.
                "32"
            ],
        },
        "multi file, no file name, with line index": {
            "args": [
                [DUMMY_FILE_1, DUMMY_FILE_2],
                ["foobar"],
            ],
            "kwargs": {
                "count_results": False,
                "total_results": False,
                "with_file_name": False,
                "with_line_number": True,
            },
            "returns": [
                "3:foobar",
                "3:foobar",
            ],
        },
        "multi file, no file name, with count": {
            "args": [
                [DUMMY_FILE_1, DUMMY_FILE_2],
                ["foo"],
            ],
            "kwargs": {
                "count_results": True,
                "total_results": False,
                "with_file_name": False,
                "with_line_number": False,
            },
            "returns": [
                "16",
                "16",
            ],
        },
        "multi file, no file name, with total": {
            "args": [
                [DUMMY_FILE_1, DUMMY_FILE_2],
                ["foo"],
            ],
            "kwargs": {
                "count_results": False,
                "total_results": True,
                "with_file_name": False,
                "with_line_number": False,
            },
            "returns": [
                "32",
            ],
        },
        "case sensitive": {
            "args": [
                [DUMMY_FILE_1],
                ["fOoBaR"],
            ],
            "kwargs": {"ignore_case": False},
            "returns": [
                # No match expected.
            ],
        },
        "case insensitive": {
            "args": [
                [DUMMY_FILE_1],
                ["fOoBaR"],
            ],
            "kwargs": {"ignore_case": True},
            "returns": ["foobar"],
        },
        "special character exact": {
            "args": [
                [DUMMY_FILE_1],
                ["barfoo\\+"],
            ],
            "returns": [
                "barfoo+",
            ],
        },
        "special character regex": {
            "args": [
                [DUMMY_FILE_1],
                ["barfoo+"],
            ],
            "returns": [
                "barfoo",
                "barfoo+",
            ],
        },
        "only matching with single level groups": {
            "args": [
                [DUMMY_FILE_1],
                ["dummy file to test|sync with"],
            ],
            "kwargs": {"only_matching": True},
            "returns": [
                "dummy file to test",
                "sync with",
                "dummy file to test",
                "sync with",
            ],
        },
        "only matching with redundant inner nested level group": {
            "args": [
                [DUMMY_FILE_1],
                ["dummy file (to|to test)|sync with"],
            ],
            "kwargs": {"only_matching": True},
            "returns": [
                "dummy file to",
                "sync with",
                "dummy file to",
                "sync with",
            ],
        },
        "only matching pattern without only matching enabled": {
            "args": [
                [DUMMY_FILE_1],
                ["dummy file to test|sync with"],
            ],
            "kwargs": {"only_matching": False},
            "returns": [
                "# Primary dummy file to test patterns. Keep in sync with greptest2.txt.",
                "# Primary dummy file to test patterns. Keep in sync with greptest2.txt.",
            ],
        },
        "multiple unique patterns": {
            "args": [
                [DUMMY_FILE_1],
                [
                    "foobar",
                    "extra foo bar",
                ],
            ],
            "kwargs": {
                "with_file_name": True,
                "with_line_number": True,
            },
            "returns": ["greptest1.txt:3:foobar", "greptest1.txt:16:extra foo bar"],
        },
        "Multiple redundant patterns": {
            "args": [
                [DUMMY_FILE_1],
                [
                    "foobar",
                    "fo{2}bar",
                    "fo+bar",
                ],
            ],
            "kwargs": {
                "with_file_name": True,
                "with_line_number": True,
            },
            "returns": [
                "greptest1.txt:3:foobar",
            ],
        },
    },
    "parse_args": {
        "leading pattern positional and file positionals": {
            "args": [
                shlex.split("p1 f1 f2 f3"),
            ],
            "attributes": {
                "files": ["f1", "f2", "f3"],
                "pattern": "p1",
            },
        },
        "intermixed pattern positional, trailing file positionals, and pattern optionals": {
            "args": [
                shlex.split("-e p2 p1 -e p3 f1 f2"),
            ],
            "attributes": {
                "files": ["f1", "f2"],
                "pattern": "p1",
                "patterns": ["p2", "p3"],
            },
        },
        "pattern positional, intermixed file positionals, and pattern optionals": {
            "args": [
                shlex.split("p1 f1 -e p2 f2 -e p3 f3 f4"),
            ],
            "attributes": {
                "files": ["f1", "f2", "f3", "f4"],
                "pattern": "p1",
                "patterns": ["p2", "p3"],
            },
        },
    },
    "to_basic_regular_expressions": {
        "no changes, no special characters": {
            "args": [
                ["test"],
            ],
            "returns": ["test"],
        },
        "no changes, BRE compatible special characters": {
            "args": [
                ["^test.*[test]$"],
            ],
            "returns": ["^test.*[test]$"],
        },
        "BRE and PCRE special characters": {
            "args": [
                ["^test.*[test]+?(){}|$"],
            ],
            "returns": [r"^test.*[test]\+\?\(\)\{\}\|$"],
        },
        "BRE, PCRE, and escaped special characters": {
            "args": [
                [r"^test.*[test]+?(){}|\^\$\*\.\[\]\+\?\(\)\{\}\|$"],
            ],
            "returns": [r"^test.*[test]\+\?\(\)\{\}\|\^\$\*\.\[\]+?(){}|$"],
        },
        "Valid as PCRE, but not valid as BRE": {
            "args": [
                [r"data \((?P<v0>.*?) (?P<v1>.*?)"],
            ],
            "raises": ValueError,
        },
    },
    "to_gnu_regular_expressions": {
        "no changes, no escapes": {
            "args": [
                ["<foo>"],
            ],
            "returns": ["<foo>"],
        },
        "GNU word boundaries swapped": {
            "args": [
                [r"<foo>\<foo\>"],
            ],
            "returns": [r"<foo>\bfoo\b"],
        },
        "GNU word boundaries swapped, escaped boundaries skipped": {
            "args": [
                [r"<foo>\<foo\>\\<foo\\>"],
            ],
            "returns": [r"<foo>\bfoo\b\\<foo\\>"],
        },
    },
}


@pytest.fixture(autouse=True)
def no_file_load(monkeypatch: Any) -> None:
    """Prevent tests from loading external files, and instead mock the lines."""

    def mock_opener(file: str, *args: Any, **kwargs: Any) -> io.StringIO:
        return io.StringIO(FAKE_FILES.get(file, ""))

    monkeypatch.setattr(builtins, "open", mock_opener)


@pytest.mark.parametrize_test_case("test_case", TEST_CASES["check_hyperscan_compatibility"])
def test_check_hyperscan_compatibility(test_case: dict, function_tester: Callable) -> None:
    """Unit tests for verifying Hyperscan pattern compatibility."""
    function_tester(test_case, utils.check_compatibility)


@pytest.mark.parametrize_test_case("test_case", TEST_CASES["get_argparse_files"])
def test_get_argparse_files(test_case: dict, function_tester: Callable) -> None:
    """Tests for get_argparse_files function."""
    function_tester(test_case, hyperscanner.get_argparse_files)


@pytest.mark.parametrize_test_case("test_case", TEST_CASES["get_argparse_patterns"])
def test_get_argparse_patterns(test_case: dict, function_tester: Callable) -> None:
    """Tests for get_argparse_patterns function."""
    function_tester(test_case, hyperscanner.get_argparse_patterns)


@pytest.mark.parametrize_test_case("test_case", TEST_CASES["grep"])
@pytest.mark.skipif(
    sys.platform != "linux",
    reason="Hyperscan libraries only support Linux",
)
def test_grep(test_case: dict, function_tester: Callable) -> None:
    """Tests for grep function."""
    function_tester(test_case, hyperscanner.grep)


@pytest.mark.parametrize_test_case("test_case", TEST_CASES["hyperscan"])
@pytest.mark.skipif(
    sys.platform != "linux",
    reason="Hyperscan libraries only support Linux",
)
def test_hyperscan(test_case: dict, capsys: Any, function_tester: Callable) -> None:
    """Tests for hyperscan function."""

    def _grep_helper(*args: Any, **kwargs: Any) -> list:
        """Helper to run hyperscan and capture output for comparisons."""
        utils.scan(*args, **kwargs)
        capture = capsys.readouterr()
        stdout = capture.out.splitlines()
        return stdout

    function_tester(test_case, _grep_helper)


@pytest.mark.parametrize_test_case("test_case", TEST_CASES["parallel_grep"])
@pytest.mark.skipif(
    sys.platform != "linux",
    reason="Hyperscan libraries only support Linux",
)
def test_parallel_grep(test_case: dict, capsys: Any, function_tester: Callable) -> None:
    """Tests for parallel_grep function."""

    def parallel_grep_helper(*args: Any, **kwargs: Any) -> list:
        """Helper to run parallel_grep and capture output for comparisons."""
        hyperscanner.parallel_grep(*args, **kwargs)
        capture = capsys.readouterr()
        stdout = capture.out.splitlines()
        root = os.path.dirname(__file__)
        # Strip off the leading file name in output to keep the tests portable across systems.
        cleaned = [line.replace(f"{root}/", "") for line in stdout]
        return cleaned

    function_tester(test_case, parallel_grep_helper)


@pytest.mark.parametrize_test_case("test_case", TEST_CASES["parse_args"])
def test_parse_args(test_case: dict, function_tester: Callable) -> None:
    """Tests for parse_args function."""
    function_tester(test_case, hyperscanner.parse_args)


@pytest.mark.parametrize_test_case("test_case", TEST_CASES["to_basic_regular_expressions"])
def test_to_basic_regular_expressions(test_case: dict, function_tester: Callable) -> None:
    """Tests for to_basic_regular_expressions function."""
    function_tester(test_case, hyperscanner.to_basic_regular_expressions)


@pytest.mark.parametrize_test_case("test_case", TEST_CASES["to_gnu_regular_expressions"])
def test_to_gnu_regular_expressions(test_case: dict, function_tester: Callable) -> None:
    """Tests for to_gnu_regular_expressions function."""
    function_tester(test_case, hyperscanner.to_gnu_regular_expressions)
