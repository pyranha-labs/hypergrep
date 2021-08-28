"""Test cases for the pyhypergrep module."""

import builtins
import argparse
import io
import os
import pytest
import shlex
import sys

from typing import Any
from typing import Callable

from pyhypergrep import hyperscanner
from pyhypergrep.common import hyper_utils


def _dummy_callback(matches: list, count: int) -> None:
    """Callback for C library to send results."""
    for index in range(count):
        match = matches[index]
        line = match.line.decode(errors='ignore')
        print(f'{match.line_number}:{line.rstrip()}')


DUMMY_FILE_1 = os.path.join(os.path.dirname(__file__), 'greptest1.txt')
DUMMY_FILE_2 = os.path.join(os.path.dirname(__file__), 'greptest2.txt')
FAKE_FILES = {
    'regex.txt': 'filepattern1\nfilepattern2',
}
TEST_FILE = os.path.join(os.path.dirname(__file__), 'dummyfile.txt')
TEST_CASES = {
    'argparse_namespace_comparator': {
        'matched': {
            'args': [
                argparse.Namespace(
                    files=['f1', 'f2', 'f3'],
                    pattern='p1',
                ),
                argparse.Namespace(
                    files=['f1', 'f2', 'f3'],
                    pattern='p1',
                ),
            ],
            'expected': None
        },
        'mismatched': {
            'args': [
                argparse.Namespace(
                    files=['f1', 'f2', 'f3'],
                    pattern='p1',
                ),
                argparse.Namespace(
                    files=['f1', 'f2'],
                    pattern='p2',
                ),
            ],
            'raises': AssertionError
        },
    },
    'check_hyperscan_compatibility': {
        'PCRE and Hyperscan compatible': {
            'args': [
                ['foobar']
            ],
            'expected': 0,
        },
        'PCRE compatible but Hyperscan incompatible': {
            # Negative lookbehind example taken from: unit/hyperscan/bad_patterns.cpp
            'args': [
                ['(?<!foo)bar']
            ],
            'expected': 4,
        },
    },
    'get_argparse_files': {
        'leading pattern positional and file positionals': {
            'args': [
                hyperscanner.parse_args(shlex.split('pattern1 file1 file2 file3')),
            ],
            'expected': ['file1', 'file2', 'file3']
        },
        'Leading pattern positional and pattern optional': {
            # See hyperscanner.get_argparse_files for explanation of why pattern1 is considered a file in this scenario.
            'args': [
                hyperscanner.parse_args(shlex.split('pattern1 -e pattern2 file1')),
            ],
            'expected': ['pattern1', 'file1']
        },
        'Leading pattern positional and pattern file optional': {
            # See hyperscanner.get_argparse_files for explanation of why pattern1 is considered a file in this scenario.
            'args': [
                hyperscanner.parse_args(shlex.split('pattern1 -f regex.txt file1')),
            ],
            'expected': ['pattern1', 'file1']
        },
        'Leading pattern positional, pattern optional, and pattern file optional': {
            # See hyperscanner.get_argparse_files for explanation of why pattern1 is considered a file in this scenario.
            'args': [
                hyperscanner.parse_args(shlex.split('pattern1 -e pattern2 -f regex.txt file1')),
            ],
            'expected': ['pattern1', 'file1']
        },
        'intermixed pattern positional, trailing file positionals, and pattern optionals': {
            # See hyperscanner.get_argparse_files for explanation of why pattern1 is considered a file in this scenario.
            'args': [
                hyperscanner.parse_args(shlex.split('-e pattern2 pattern1 -e pattern3 file1 file2')),
            ],
            'expected': ['pattern1', 'file1', 'file2']
        },
        'pattern positional, intermixed file positionals, and pattern optionals': {
            # See hyperscanner.get_argparse_files for explanation of why pattern1 is considered a file in this scenario.
            'args': [
                hyperscanner.parse_args(shlex.split('pattern1 file1 -e pattern2 file2 -e pattern3 file3 f4')),
            ],
            'expected': ['pattern1', 'file1', 'file2', 'file3', 'f4']
        },
    },
    'get_argparse_patterns': {
        'leading pattern positional and file positionals': {
            'args': [
                hyperscanner.parse_args(shlex.split('pattern1 file1 file2 file3')),
            ],
            'expected': ['pattern1']
        },
        'Leading pattern positional and pattern optional': {
            # See hyperscanner.get_argparse_patterns for explanation of why pattern1 is not considered a pattern in this scenario.
            'args': [
                hyperscanner.parse_args(shlex.split('pattern1 -e pattern2 file1')),
            ],
            'expected': ['pattern2']
        },
        'Leading pattern positional and pattern file optional': {
            # See hyperscanner.get_argparse_patterns for explanation of why pattern1 is not considered a pattern in this scenario.
            'args': [
                hyperscanner.parse_args(shlex.split('pattern1 -f regex.txt file1')),
            ],
            'expected': ['filepattern1', 'filepattern2']
        },
        'Leading pattern positional, pattern optional, and pattern file optional': {
            # See hyperscanner.get_argparse_patterns for explanation of why pattern1 is not considered a pattern in this scenario.
            'args': [
                hyperscanner.parse_args(shlex.split('pattern1 -e pattern2 -f regex.txt file1')),
            ],
            'expected': ['pattern2', 'filepattern1', 'filepattern2']
        },
        'intermixed pattern positional, trailing file positionals, and pattern optionals': {
            # See hyperscanner.get_argparse_patterns for explanation of why pattern1 is not considered a pattern in this scenario.
            'args': [
                hyperscanner.parse_args(shlex.split('-e pattern2 pattern1 -e pattern3 file1 file2')),
            ],
            'expected': ['pattern2', 'pattern3']
        },
        'pattern positional, intermixed file positionals, and pattern optionals': {
            # See hyperscanner.get_argparse_patterns for explanation of why pattern1 is not considered a pattern in this scenario.
            'args': [
                hyperscanner.parse_args(shlex.split('pattern1 file1 -e pattern2 file2 -e pattern3 file3 f4')),
            ],
            'expected': ['pattern2', 'pattern3']
        },
    },
    'hyperscan': {
        'one pattern': {
            'args': [
                TEST_FILE,
                ['bar'],
                _dummy_callback,
            ],
            'expected': [
                '1:foobar',
                '2:barfoo',
            ]
        },
        'two patterns': {
            'args': [
                TEST_FILE,
                [
                    'bar',
                    'food',
                ],
                _dummy_callback,
            ],
            'expected': [
                '1:foobar',
                '2:barfoo',
                '3:food',
            ]
        },
    },
    'grep': {
        'one pattern, no index': {
            'args': [
                TEST_FILE,
                ['bar'],
                False,
                False,
                False,
                False,
            ],
            'expected': [
                'foobar\n',
                'barfoo\n'
            ]
        },
        'one pattern, with index': {
            'args': [
                TEST_FILE,
                ['bar'],
                False,
                True,
                False,
                False,
            ],
            'expected': [
                (2, 'foobar\n'),
                (3, 'barfoo\n'),
            ]
        },
    },
    'parallel_grep': {
        'single file, with file name': {
            'args': [
                [DUMMY_FILE_1],
                ['foobar'],
            ],
            'kwargs': {
                'count_results': False,
                'total_results': False,
                'with_file_name': True,
                'with_line_number': False,
            },
            'expected': [
                'greptest1.txt:foobar',
            ]
        },
        'single file, with file name and line index': {
            'args': [
                [DUMMY_FILE_1],
                ['foobar'],
            ],
            'kwargs': {
                'count_results': False,
                'total_results': False,
                'with_file_name': True,
                'with_line_number': True,
            },
            'expected': [
                'greptest1.txt:3:foobar',
            ]
        },
        'single file, with file name and count': {
            'args': [
                [DUMMY_FILE_1],
                ['foo'],
            ],
            'kwargs': {
                'count_results': True,
                'total_results': False,
                'with_file_name': True,
                'with_line_number': False,
            },
            'expected': [
                'greptest1.txt:16',
            ]
        },
        'single file, with file name and total': {
            'args': [
                [DUMMY_FILE_1],
                ['foo'],
            ],
            'kwargs': {
                'count_results': False,
                'total_results': True,
                'with_file_name': True,
                'with_line_number': False,
            },
            'expected': [
                # It is expected for total to not show a file name, it is a total. This ensures expected behavior.
                '16',
            ]
        },
        'single file, no file name, with line index': {
            'args': [
                [DUMMY_FILE_1],
                ['foobar'],
            ],
            'kwargs': {
                'count_results': False,
                'total_results': False,
                'with_file_name': False,
                'with_line_number': True,
            },
            'expected': [
                '3:foobar',
            ]
        },
        'single file, no file name, with count': {
            'args': [
                [DUMMY_FILE_1],
                ['foo'],
            ],
            'kwargs': {
                'count_results': True,
                'total_results': False,
                'with_file_name': False,
                'with_line_number': False,
            },
            'expected': [
                '16',
            ]
        },
        'single file, no file name, with total': {
            'args': [
                [DUMMY_FILE_1],
                ['foo'],
            ],
            'kwargs': {
                'count_results': False,
                'total_results': True,
                'with_file_name': False,
                'with_line_number': False,
            },
            'expected': [
                '16',
            ]
        },
        'multi file, with file name': {
            'args': [
                [DUMMY_FILE_1, DUMMY_FILE_2],
                ['foobar'],
            ],
            'kwargs': {
                'count_results': False,
                'total_results': False,
                'with_file_name': True,
                'with_line_number': False,
            },
            'expected': [
                'greptest1.txt:foobar',
                'greptest2.txt:foobar',
            ]
        },
        'multi file, with file name and line index': {
            'args': [
                [DUMMY_FILE_1, DUMMY_FILE_2],
                ['foobar'],
            ],
            'kwargs': {
                'count_results': False,
                'total_results': False,
                'with_file_name': True,
                'with_line_number': True,
            },
            'expected': [
                'greptest1.txt:3:foobar',
                'greptest2.txt:3:foobar',
            ]
        },
        'multi file, with file name and count': {
            'args': [
                [DUMMY_FILE_1, DUMMY_FILE_2],
                ['foo'],
            ],
            'kwargs': {
                'count_results': True,
                'total_results': False,
                'with_file_name': True,
                'with_line_number': False,
            },
            'expected': [
                'greptest1.txt:16',
                'greptest2.txt:16',
            ]
        },
        'multi file, with file name and total': {
            'args': [
                [DUMMY_FILE_1, DUMMY_FILE_2],
                ['foo'],
            ],
            'kwargs': {
                'count_results': False,
                'total_results': True,
                'with_file_name': True,
                'with_line_number': False,
            },
            'expected': [
                # It is expected for total to not show a file name, it is a total. This ensures expected behavior.
                '32'
            ]
        },
        'multi file, no file name, with line index': {
            'args': [
                [DUMMY_FILE_1, DUMMY_FILE_2],
                ['foobar'],
            ],
            'kwargs': {
                'count_results': False,
                'total_results': False,
                'with_file_name': False,
                'with_line_number': True,
            },
            'expected': [
                '3:foobar',
                '3:foobar',
            ]
        },
        'multi file, no file name, with count': {
            'args': [
                [DUMMY_FILE_1, DUMMY_FILE_2],
                ['foo'],
            ],
            'kwargs': {
                'count_results': True,
                'total_results': False,
                'with_file_name': False,
                'with_line_number': False,
            },
            'expected': [
                '16',
                '16',
            ]
        },
        'multi file, no file name, with total': {
            'args': [
                [DUMMY_FILE_1, DUMMY_FILE_2],
                ['foo'],
            ],
            'kwargs': {
                'count_results': False,
                'total_results': True,
                'with_file_name': False,
                'with_line_number': False,
            },
            'expected': [
                '32',
            ]
        },
        'case sensitive': {
            'args': [
                [DUMMY_FILE_1],
                ['fOoBaR'],
            ],
            'kwargs': {
                'ignore_case': False
            },
            'expected': [
                # No match expected.
            ]
        },
        'case insensitive': {
            'args': [
                [DUMMY_FILE_1],
                ['fOoBaR'],
            ],
            'kwargs': {
                'ignore_case': True
            },
            'expected': [
                'foobar'
            ]
        },
        'special character exact': {
            'args': [
                [DUMMY_FILE_1],
                ['barfoo\\+'],
            ],
            'expected': [
                'barfoo+',
            ]
        },
        'special character regex': {
            'args': [
                [DUMMY_FILE_1],
                ['barfoo+'],
            ],
            'expected': [
                'barfoo',
                'barfoo+',
            ]
        },
    },
    'parse_args': {
        'leading pattern positional and file positionals': {
            'args': [
                shlex.split('p1 f1 f2 f3'),
            ],
            'expected': argparse.Namespace(
                files=['f1', 'f2', 'f3'],
                pattern='p1',
            )
        },
        'intermixed pattern positional, trailing file positionals, and pattern optionals': {
            'args': [
                shlex.split('-e p2 p1 -e p3 f1 f2'),
            ],
            'expected': argparse.Namespace(
                files=['f1', 'f2'],
                pattern='p1',
                patterns=['p2', 'p3'],
            )
        },
        'pattern positional, intermixed file positionals, and pattern optionals': {
            'args': [
                shlex.split('p1 f1 -e p2 f2 -e p3 f3 f4'),
            ],
            'expected': argparse.Namespace(
                files=['f1', 'f2', 'f3', 'f4'],
                pattern='p1',
                patterns=['p2', 'p3'],
            )
        },
    },
    'to_basic_regular_expressions': {
        'no changes, no special characters': {
            'args': [
                ['test'],
            ],
            'expected': ['test']
        },
        'no changes, BRE compatible special characters': {
            'args': [
                ['^test.*[test]$'],
            ],
            'expected': ['^test.*[test]$']
        },
        'BRE and PCRE special characters': {
            'args': [
                ['^test.*[test]+?(){}|$'],
            ],
            'expected': [r'^test.*[test]\+\?\(\)\{\}\|$']
        },
        'BRE, PCRE, and escaped special characters': {
            'args': [
                [r'^test.*[test]+?(){}|\^\$\*\.\[\]\+\?\(\)\{\}\|$'],
            ],
            'expected': [r'^test.*[test]\+\?\(\)\{\}\|\^\$\*\.\[\]+?(){}|$']
        },
        'Valid as PCRE, but not valid as BRE': {
            'args': [
                [r'data \((?P<v0>.*?) (?P<v1>.*?)'],
            ],
            'raises': ValueError
        },
    },
    'to_gnu_regular_expressions': {
        'no changes, no escapes': {
            'args': [
                ['<foo>'],
            ],
            'expected': ['<foo>']
        },
        'GNU word boundaries swapped': {
            'args': [
                [r'<foo>\<foo\>'],
            ],
            'expected': [r'<foo>\bfoo\b']
        },
        'GNU word boundaries swapped, escaped boundaries skipped': {
            'args': [
                [r'<foo>\<foo\>\\<foo\\>'],
            ],
            'expected': [r'<foo>\bfoo\b\\<foo\\>']
        },
    },
}


@pytest.fixture(autouse=True)
def no_file_load(monkeypatch: Any) -> None:
    """Prevent tests from loading external files, and instead mock the lines."""
    def mock_opener(file: str, *args, **kwargs) -> io.StringIO:
        return io.StringIO(FAKE_FILES.get(file, ''))
    monkeypatch.setattr(builtins, 'open', mock_opener)


def argparse_namespace_comparator(result: argparse.Namespace, expected_result: argparse.Namespace) -> None:
    """Helper to simplify argparse namespace testing by only comparing declared values in an expected result.

    Args:
        result: Actual result from a test containing all namespace values.
        expected_result: User defined result containing only values to compare.

    Raises:
        AssertionError if any of the values in expected result do not match result.
    """
    for key, value in expected_result.__dict__.items():
        assert getattr(result, key) == value


def run_basic_test_case(test_case: dict, context: Callable, comparator: Callable = None) -> None:
    """Run a basic test_case configuration against the given context.

    Args:
        test_case: A dictionary containing configuration parameters for testing a callable.
        context: A callable to pass args and kwargs that will return value to compare.
        comparator: A function to use for comparing the expected_results and result.
            Defaults to doing a direct "==" comparison.

    Example:
        test_case (test raising an error) = {'raises': ValueError, 'kwargs': {'value': None}}
        test_case (test getting expected result) = {'expected': 10, 'args': [5, 12]}
    """
    args = test_case.get('args', [])
    kwargs = test_case.get('kwargs', {})
    raises = test_case.get('raises')
    if raises:
        with pytest.raises(raises):
            context(*args, **kwargs)
    else:
        expected = test_case.get('expected')
        result = context(*args, **kwargs)
        message = f'Got an unexpected result.\n\nExpected: {expected}\n\nActual: {result}'
        if comparator:
            comparator(result, expected)
        else:
            assert result == expected, message


@pytest.mark.parametrize(
    'test_case',
    list(TEST_CASES['check_hyperscan_compatibility'].values()),
    ids=list(TEST_CASES['check_hyperscan_compatibility'].keys()),
)
def test_check_hyperscan_compatibility(test_case: dict) -> None:
    """Unit tests for verifying Hyperscan pattern compatibility."""
    run_basic_test_case(test_case, hyper_utils.check_hyperscan_compatibility)


@pytest.mark.parametrize(
    'test_case',
    list(TEST_CASES['get_argparse_files'].values()),
    ids=list(TEST_CASES['get_argparse_files'].keys()),
)
def test_get_argparse_files(test_case: dict) -> None:
    """Tests for get_argparse_files function."""
    run_basic_test_case(test_case, hyperscanner.get_argparse_files)


@pytest.mark.parametrize(
    'test_case',
    list(TEST_CASES['get_argparse_patterns'].values()),
    ids=list(TEST_CASES['get_argparse_patterns'].keys()),
)
def test_get_argparse_patterns(test_case: dict) -> None:
    """Tests for get_argparse_patterns function."""
    run_basic_test_case(test_case, hyperscanner.get_argparse_patterns)


@pytest.mark.parametrize(
    'test_case',
    list(TEST_CASES['grep'].values()),
    ids=list(TEST_CASES['grep'].keys()),
)
@pytest.mark.skipif(
    sys.platform != 'linux',
    reason='Hyperscan libraries only support Linux',
)
def test_grep(test_case: dict) -> None:
    """Tests for grep function."""
    run_basic_test_case(test_case, hyperscanner.grep)


@pytest.mark.parametrize(
    'test_case',
    list(TEST_CASES['hyperscan'].values()),
    ids=list(TEST_CASES['hyperscan'].keys()),
)
@pytest.mark.skipif(
    sys.platform != 'linux',
    reason='Hyperscan libraries only support Linux',
)
def test_hyperscan(test_case: dict, capsys: Any) -> None:
    """Tests for hyperscan function."""
    def _grep_helper(*args, **kwargs) -> list:
        """Helper to run hyperscan and capture output for comparisons."""
        hyper_utils.hyperscan(*args, **kwargs)
        capture = capsys.readouterr()
        stdout = capture.out.splitlines()
        return stdout
    run_basic_test_case(test_case, _grep_helper)


@pytest.mark.parametrize(
    'test_case',
    list(TEST_CASES['argparse_namespace_comparator'].values()),
    ids=list(TEST_CASES['argparse_namespace_comparator'].keys()),
)
def test_namespace_comparator(test_case: dict) -> None:
    """Tests for argparse_namespace_comparator function."""
    run_basic_test_case(test_case, argparse_namespace_comparator)


@pytest.mark.parametrize(
    'test_case',
    list(TEST_CASES['parallel_grep'].values()),
    ids=list(TEST_CASES['parallel_grep'].keys()),
)
@pytest.mark.skipif(
    sys.platform != 'linux',
    reason='Hyperscan libraries only support Linux',
)
def test_parallel_grep(test_case: dict, capsys: Any) -> None:
    """Tests for parallel_grep function."""
    def parallel_grep_helper(*args, **kwargs) -> list:
        """Helper to run parallel_grep and capture output for comparisons."""
        hyperscanner.parallel_grep(*args, **kwargs)
        capture = capsys.readouterr()
        stdout = capture.out.splitlines()
        root = os.path.dirname(__file__)
        # Strip off the leading file name in output to keep the tests portable across systems.
        cleaned = [line.replace(f'{root}/', '') for line in stdout]
        return cleaned
    run_basic_test_case(test_case, parallel_grep_helper)


@pytest.mark.parametrize(
    'test_case',
    list(TEST_CASES['parse_args'].values()),
    ids=list(TEST_CASES['parse_args'].keys()),
)
def test_parse_args(test_case: dict) -> None:
    """Tests for parse_args function."""
    run_basic_test_case(test_case, hyperscanner.parse_args, comparator=argparse_namespace_comparator)


@pytest.mark.parametrize(
    'test_case',
    list(TEST_CASES['to_basic_regular_expressions'].values()),
    ids=list(TEST_CASES['to_basic_regular_expressions'].keys()),
)
def test_to_basic_regular_expressions(test_case: dict) -> None:
    """Tests for to_basic_regular_expressions function."""
    run_basic_test_case(test_case, hyperscanner.to_basic_regular_expressions)


@pytest.mark.parametrize(
    'test_case',
    list(TEST_CASES['to_gnu_regular_expressions'].values()),
    ids=list(TEST_CASES['to_gnu_regular_expressions'].keys()),
)
def test_to_gnu_regular_expressions(test_case: dict) -> None:
    """Tests for to_gnu_regular_expressions function."""
    run_basic_test_case(test_case, hyperscanner.to_gnu_regular_expressions)
