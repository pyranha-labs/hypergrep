"""Setup configuration and dependencies for the pyhypergrep library."""

import os
import setuptools

ROOT_DIR = os.path.dirname(os.path.realpath(__file__))

# Additional configuration and data files installed with the package
PACKAGE_DATA = {
    'pyhypergrep.common.shared': ['libhs.so.5', 'libhyperscanner.so'],
}


def _find_version() -> str:
    """Locate semantic version from a text file in a compatible format with setuptools."""
    # Do not import the module within the library, as this can cause an infinite import. Read manually.
    init_file = os.path.join(ROOT_DIR, 'pyhypergrep', '__init__.py')
    with open(init_file, 'rt') as file_in:
        for line in file_in.readlines():
            if '__version__' in line:
                # Example:
                # __version__ = '1.5.0' -> 1.5.0
                version = line.split()[2].replace("'", '')
    return version


setuptools.setup(
    name='pyhypergrep',
    version=_find_version(),
    description='Utilities for scanning text files with Intel Hyperscan.',
    maintainer='David Fritz',
    maintainer_email='dfrtzdev@gmail.com',
    url='https://github.com/dfrtz/pyhypergrep',
    packages=setuptools.find_packages(ROOT_DIR, include=['pyhypergrep*'], exclude=['*test']),
    package_data=PACKAGE_DATA,
    python_requires='>=3.7',
    entry_points={
        'console_scripts': [
            'pyhypergrep = pyhypergrep.hyperscanner:main',
        ]
    },
)
