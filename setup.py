# This should be only one line. If it must be multi-line, indent the second
# line onwards to keep the PKG-INFO file format intact.
"""Scans a Nix store for derivations that are affected by vulnerabilities."""

from setuptools import setup, find_packages
import os.path


def project_path(*names):
    return os.path.join(os.path.dirname(__file__), *names)


with open(project_path('VERSION')) as f:
    version = f.read().strip()

long_description = []

for rst in ['README.rst', 'HACKING.rst', 'CHANGES.rst']:
    with open(project_path(rst)) as f:
        long_description.append(f.read())

setup(
    name='vulnix',
    version=version,
    install_requires=[
        'click>=6.7',
        'colorama>=0.3',
        'lxml>=4',
        'pyyaml>=3.13,<6',
        'requests>=2.18',
        'toml>=0.9',
        'ZODB>=5.4',
    ],
    extras_require={
        'test': [
            'freezegun>0.3',
            'pytest>=3.2',
            'pytest-cov>=2.5',
            'pytest-flake8',
            'pytest-runner>=2.11,<3dev',
            'pytest-timeout>=1.2',
            'setuptools_scm>=1.15',
        ],
    },
    entry_points="""
        [console_scripts]
            vulnix = vulnix.main:main
    """,
    author='Flying Circus Internet Operations GmbH',
    author_email='mail@flyingcircus.io',
    license='BSD-3-Clause',
    url='https://github.com/flyingcircusio/vulnix',
    keywords='security',
    classifiers="""\
Development Status :: 5 - Production/Stable
Environment :: Console
Intended Audience :: System Administrators
License :: OSI Approved :: BSD License
Operating System :: POSIX
Programming Language :: Python
Programming Language :: Python :: 3 :: Only
Programming Language :: Python :: 3.5
Programming Language :: Python :: 3.6
Programming Language :: Python :: 3.7
Topic :: System :: Systems Administration
"""[:-1].split('\n'),
    description=__doc__.strip(),
    long_description='\n\n'.join(long_description),
    packages=find_packages('src'),
    package_dir={'': 'src'},
    include_package_data=True,
    zip_safe=False
)
