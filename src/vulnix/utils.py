import itertools
import logging
import re
import subprocess
import sys
import tempfile
import time

_log = logging.getLogger(__name__)


def batch(iterable, size, callable):
    b = size
    for x in iterable:
        yield x
        b -= 1
        if not b:
            callable()
            b = size


def call(cmd):
    """Executes `cmd` and swallow stderr iff returncode is 0."""
    with tempfile.TemporaryFile(prefix='stderr') as capture:
        try:
            output = subprocess.check_output(cmd, stderr=capture)
        except subprocess.CalledProcessError:
            capture.seek(0)
            sys.stderr.write(capture.read().decode('ascii', errors='replace'))
            raise
    return output.decode()


class Timer:

    def __init__(self, section):
        self.section = section

    def __enter__(self):
        _log.debug('>>> %s', self.section)
        self.start = time.clock()
        return self

    def __exit__(self, *exc):
        self.end = time.clock()
        self.interval = self.end - self.start
        _log.debug('<<< %s %.2fs', self.section, self.interval)
        return False  # re-raise


R_COMP = re.compile(r'([0-9]+|[^0-9.-]+)')


def split_components(vers):
    return [c for c in R_COMP.split(vers) if c not in ('', '.', '-')]


def components_lt(left, right):
    try:
        lnum = int(left)
    except (ValueError):
        lnum = None
    try:
        rnum = int(right)
    except (ValueError):
        rnum = None
    if lnum is not None and rnum is not None:
        return lnum < rnum
    if left == '' and rnum is not None:
        return True
    if left == 'pre' and right != 'pre':
        return True
    if right == 'pre':
        return False
    if rnum is not None:
        return True
    if lnum is not None:
        return False
    return left < right


def compare_versions(left, right):
    left_ = split_components(left)
    right_ = split_components(right)
    for (lc, rc) in itertools.zip_longest(left_, right_, fillvalue=''):
        if lc == rc:
            continue
        if components_lt(lc, rc):
            return -1
        if components_lt(rc, lc):
            return 1
    return 0
