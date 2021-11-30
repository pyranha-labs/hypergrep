# PyHyperGrep

[![python: python3.7+](https://img.shields.io/badge/python-3.7-blue)](https://docs.python.org/3.7/)
[![python style: google](https://img.shields.io/badge/python%20style-google-blue)](https://google.github.io/styleguide/pyguide.html)
[![code quality: pylint](https://img.shields.io/badge/code%20quality-pylint-green)](https://github.com/PyCQA/pylint)
[![code style: pycodestyle](https://img.shields.io/badge/code%20style-pycodestyle-green)](https://github.com/PyCQA/pycodestyle)
[![doc style: pydocstyle](https://img.shields.io/badge/doc%20style-pydocstyle-green)](https://github.com/PyCQA/pydocstyle)
[![license: MIT](https://img.shields.io/badge/license-MIT-lightgrey)](https://www.apache.org/licenses/LICENSE-2.0)

PyHyperGrep is a Python + Intel Hyperscan Global Regular Expression Processing library. While a standard grep is
designed to print, this is designed to allow full control over processing matches. The library supports scanning
plaintext, gzip, and ztsd compressed files for regular expressions, and customizing the action to take when matched.

For full information on the amazing performance that can be obtained through Intel Hyperscan with, refer to:  
[Hyperscan](https://github.com/intel/hyperscan)


## Examples

Read a file with the example command:
```
# pyhypergrep <regex> <file>
pyhypergrep/scanner.py pattern ./pyhypergrep/pyhypergrep/scanner.py
```

Read multiple files with the hyperscanner example command:
```
# pyhypergrep <regex> <file(s)>
pyhypergrep pattern ./pyhypergrep/pyhypergrep/scanner.py
```

Perform custom operation on match:  
```
import ctypes

from pyhypergrep.common import hyper_utils

def on_match(matches: list, count: int) -> None:
    for index in range(count):
        match = matches[index]
        line = match.line.decode(errors='ignore')
        print(f'Custom print: {line.rstrip()}')

hyper_utils.hyperscan(<file>, [<pattern>], on_match)
```

## Limitations
- Not all regex constructs are supported. For more information refer to [Unsupported Constructs](https://intel.github.io/hyperscan/dev-reference/compilation.html#unsupported-constructs)
- Currently only supported on Linux. May be able to be built on Windows/OSX with additional tweaks.
