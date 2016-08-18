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

for rst in ['README.rst', 'CHANGES.rst']:
    with open(project_path(rst)) as f:
        long_description.append(f.read())

setup(
    name='vulnix',
    version=version,
    install_requires=[
        'click',
        'colorama',
        'pyyaml',
        'requests',
    ],
    entry_points="""
        [console_scripts]
            vulnix = vulnix.main:main
    """,
    author='Maksim Bronsky',
    author_email='mb@flyingcircus.io',
    license='BSD (2-clause)',
    url='https://github.com/flyingcircusio/vulnix',
    keywords='security',
    classifiers="""\
License :: OSI Approved :: BSD License
Programming Language :: Python
Programming Language :: Python :: 3
Programming Language :: Python :: 3 :: Only
"""[:-1].split('\n'),
    description=__doc__.strip(),
    long_description='\n\n'.join(long_description),
    packages=find_packages('src'),
    package_dir={'': 'src'},
    include_package_data=True,
    zip_safe=False
)
