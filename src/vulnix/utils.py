import itertools
import logging
import subprocess
import sys
import tempfile
import time

_log = logging.getLogger(__name__)


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


def components_lt(left, right):
    """Port from nix/src/libexpr/names.cc"""
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


def category(char):
    """Classify `char` into: punctuation, digit, non-digit."""
    if char in ('.', '-'):
        return 0
    if char in ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9'):
        return 1
    return 2


def split_components(v):
    """Yield cohesive groups of digits or non-digits. Skip punctuation."""
    start = 0
    stop = len(v)
    while start < stop:
        cat0 = category(v[start])
        i = start + 1
        while i < stop and category(v[i]) == cat0:
            i += 1
        if cat0 != 0:
            yield v[start:i]
        start = i


def compare_versions(left, right):
    """Compare two versions with the same logic as `nix-env -u`.

    Returns -1 if `left` is older than `right`, 1 if `left` is newer
    than `right`, and 0 if both versions are considered equal.

    See https://nixos.org/nix/manual/#ssec-version-comparisons for rules
    and examples.
    """
    if left == right:
        return 0
    for (lc, rc) in itertools.zip_longest(
            split_components(left), split_components(right), fillvalue=''):
        if lc == rc:
            continue
        if components_lt(lc, rc):
            return -1
        if components_lt(rc, lc):
            return 1
    return 0


def haskeys(d, *keys):
    """Returns True if all keys are present in a nested dict `d`."""
    if len(keys) == 1:
        return keys[0] in d
    first = keys[0]
    if first in d and isinstance(d[first], dict):
        return haskeys(d[first], *keys[1:])
    return False
