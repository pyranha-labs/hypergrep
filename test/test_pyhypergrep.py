"""Test cases for the pyhypergrep module."""

import argparse
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
    'get_argparse_files': {
        'leading pattern positional and file positionals': {
            'args': [
                hyperscanner.parse_args(shlex.split('p1 f1 f2 f3')),
            ],
            'expected': ['f1', 'f2', 'f3']
        },
        'intermixed pattern positional, trailing file positionals, and pattern optionals': {
            # See hyperscanner.get_argparse_files for explanation of why p1 is considered a file in this scenario.
            'args': [
                hyperscanner.parse_args(shlex.split('-e p2 p1 -e p3 f1 f2')),
            ],
            'expected': ['p1', 'f1', 'f2']
        },
        'pattern positional, intermixed file positionals, and pattern optionals': {
            # See hyperscanner.get_argparse_files for explanation of why p1 is considered a file in this scenario.
            'args': [
                hyperscanner.parse_args(shlex.split('p1 f1 -e p2 f2 -e p3 f3 f4')),
            ],
            'expected': ['p1', 'f1', 'f2', 'f3', 'f4']
        },
    },
    'get_argparse_patterns': {
        'leading pattern positional and file positionals': {
            'args': [
                hyperscanner.parse_args(shlex.split('p1 f1 f2 f3')),
            ],
            'expected': ['p1']
        },
        'intermixed pattern positional, trailing file positionals, and pattern optionals': {
            # See hyperscanner.get_argparse_patterns for explanation of why p1 is not considered a pattern in this scenario.
            'args': [
                hyperscanner.parse_args(shlex.split('-e p2 p1 -e p3 f1 f2')),
            ],
            'expected': ['p2', 'p3']
        },
        'pattern positional, intermixed file positionals, and pattern optionals': {
            # See hyperscanner.get_argparse_patterns for explanation of why p1 is not considered a pattern in this scenario.
            'args': [
                hyperscanner.parse_args(shlex.split('p1 f1 -e p2 f2 -e p3 f3 f4')),
            ],
            'expected': ['p2', 'p3']
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
            ],
            'expected': [
                (2, 'foobar\n'),
                (3, 'barfoo\n'),
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
                ['test^$*.[]'],
            ],
            'expected': ['test^$*.[]']
        },
        'BRE and PCRE special characters': {
            'args': [
                ['test^$*.[]+?(){}|'],
            ],
            'expected': [r'test^$*.[]\+\?\(\)\{\}\|']
        },
        'BRE, PCRE, and escaped special characters': {
            'args': [
                [r'test^$*.[]+?(){}|\^\$\*\.\[\]\+\?\(\)\{\}\|'],
            ],
            'expected': [r'test^$*.[]\+\?\(\)\{\}\|\^\$\*\.\[\]+?(){}|']
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
