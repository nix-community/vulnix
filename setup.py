# This should be only one line. If it must be multi-line, indent the second
# line onwards to keep the PKG-INFO file format intact.
"""Scans a Nix store for derivations that are affected by vulnerabilities.
"""

from setuptools import setup, find_packages
import glob
import os.path


def project_path(*names):
    return os.path.join(os.path.dirname(__file__), *names)

with open(project_path('VERSION')) as f:
    version = f.read().strip()

long_description = ''

with open(project_path('README.rst')) as f:
    long_description += f.read() + '\n\n'

with open(project_path('CHANGES.rst')) as f:
    long_description += f.read() + '\n\n'

setup(
    name='vulnix',
    version=version,
    install_requires=[
        'click',
        'pyyaml',
        'requests',
    ],
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
    long_description=long_description,
    packages=find_packages('src'),
    package_dir={'': 'src'},
    include_package_data=True,
    data_files=[('', glob.glob(project_path('*.rst')))],
    zip_safe=False
)
