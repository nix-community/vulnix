import subprocess
import sys
import tempfile


def cve_url(cve_id):
    return ('https://web.nvd.nist.gov/view/vuln/detail?vulnId={}'.
            format(cve_id))


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
