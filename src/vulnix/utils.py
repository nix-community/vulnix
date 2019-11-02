import logging
import subprocess
import sys
import tempfile
import time
from semantic_version import Version

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


# XXX unused
def normalize_version(vers):
    """Try to fit a version string from the wild into SemVer.

    This is a bit hand-wavy. Apply some heuristics to make version strings seen
    in the CVE database to be accepted by Version.coerce(). Note that this may
    fail and raise a ValueError.
    """
    try:
        # try if it is accepted right away
        return Version.coerce(vers).truncate('prerelease')
    except ValueError:
        pass
    # sometimes people use meaningless prefixes
    if vers.startswith('r') or vers.startswith('v'):
        vers = vers[1:]
    # semantic_version does not accept leading zeroes anywhere
    vers = re.sub(r'0+([0-9])', r'\1', vers)
    return Version.coerce(vers).truncate('prerelease')
