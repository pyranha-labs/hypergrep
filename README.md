# HyperGrep

[![os: linux](https://img.shields.io/badge/os-linux-blue)](https://docs.python.org/3.10/)
[![python: 3.10+](https://img.shields.io/badge/python-3.10_|_3.11-blue)](https://devguide.python.org/versions)
[![python style: google](https://img.shields.io/badge/python%20style-google-blue)](https://google.github.io/styleguide/pyguide.html)
[![imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://github.com/PyCQA/isort)
[![code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![code style: pycodestyle](https://img.shields.io/badge/code%20style-pycodestyle-green)](https://github.com/PyCQA/pycodestyle)
[![doc style: pydocstyle](https://img.shields.io/badge/doc%20style-pydocstyle-green)](https://github.com/PyCQA/pydocstyle)
[![static typing: mypy](https://img.shields.io/badge/static_typing-mypy-green)](https://github.com/python/mypy)
[![linting: pylint](https://img.shields.io/badge/linting-pylint-yellowgreen)](https://github.com/PyCQA/pylint)
[![testing: pytest](https://img.shields.io/badge/testing-pytest-yellowgreen)](https://github.com/pytest-dev/pytest)
[![security: bandit](https://img.shields.io/badge/security-bandit-black)](https://github.com/PyCQA/bandit)
[![license: MIT](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

HyperGrep is a Python + Intel Hyperscan Global Regular Expression Processing library. While a standard grep is
designed to print, this is designed to allow full control over processing matches. The library supports scanning
plaintext, gzip, and ztsd compressed files for regular expressions, and customizing the action to take when matched.

For full information on the amazing performance that can be obtained through Intel Hyperscan with, refer to:  
[Hyperscan](https://github.com/intel/hyperscan)


## Table Of Contents

  * [Compatibility](#compatibility)
  * [Getting Started](#getting-started)
    * [Installation](#installation)
  * [Examples](#examples)


## Compatibility
- Not all regex constructs are supported by Hyperscan in order to guarantee performance. For more information refer to [Unsupported Constructs](https://intel.github.io/hyperscan/dev-reference/compilation.html#unsupported-constructs)
- Currently only supported on Linux. May be able to be built on Windows/OSX manually.


## Getting Started

### Installation

Install HyperGrep via pip:
```shell
pip install hypergrep
```

Or via git clone:
```shell
git clone <path to fork>
cd hypergrep
pip install .
```

Or build and install from wheel:
```shell
# Build locally.
git clone <path to fork>
cd hypergrep
make wheel

# Push dist/hypergrep*.tar.gz to environment where it will be installed.
pip install dist/hypergrep*.tar.gz
```


## Examples

Read a file with the example single threaded command:
```shell
# hypergrep <regex> <file>
hypergrep/scanner.py pattern ./hypergrep/scanner.py
```

Read multiple files with the multithreaded hyperscanner example command:
```shell
# hypergrep <regex> <file(s)>
hypergrep pattern ./hypergrep/scanner.py
```

Perform custom operation on match:
```python
from hypergrep.common import hyper_utils

def on_match(matches: list, count: int) -> None:
    for index in range(count):
        match = matches[index]
        line = match.line.decode(errors='ignore')
        print(f'Custom print: {line.rstrip()}')


hyper_utils.hyperscan(file, [pattern], on_match)
```
