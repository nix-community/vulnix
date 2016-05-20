# This should be only one line. If it must be multi-line, indent the second
# line onwards to keep the PKG-INFO file format intact.
"""Scans a Nix store for derivations that are affected by vulnerabilities.
"""

from setuptools import setup, find_packages
import glob
import os.path


def project_path(*names):
    return os.path.join(os.path.dirname(__file__), *names)


setup(
    name='vulnix',
    version='0.1.dev0',
    install_requires=[
        'pyyaml',
    ],
    extras_require={
        'test': [
        ],
    },
    entry_points="""
        [console_scripts]
            vulnix = vulnix.main:main
    """,
    author='Flying Circus Internet Operations GmbH',
    author_email='mail@flyingcircus.io',
    license='BSD (2-clause)',
    url='https://bitbucket.org/flyingcircus/vulnix',
    keywords='security',
    classifiers="""\
License :: OSI Approved :: BSD License
Programming Language :: Python
Programming Language :: Python :: 3
Programming Language :: Python :: 3 :: Only
"""[:-1].split('\n'),
    description=__doc__.strip(),
    long_description='\n\n'.join(open(project_path(name)).read() for name in (
        'README',
        'CHANGES.txt')),
    packages=find_packages('src'),
    package_dir={'': 'src'},
    include_package_data=True,
    data_files=[('', glob.glob(project_path('*.txt')))],
    zip_safe=False
)
