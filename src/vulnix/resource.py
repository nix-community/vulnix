import contextlib
import logging
import urllib
import re

_log = logging.getLogger(__name__)


class Resource:

    R_URL_LIKE = re.compile(r'^[a-z]+://')

    def __init__(self, source, timeout=60):
        self.source = source
        self.remote = self.R_URL_LIKE.match(source)
        self.timeout = timeout

    @contextlib.contextmanager
    def open(self):
        if self.remote:
            yield urllib.request.urlopen(
                self.source, timeout=self.timeout)
        else:
            yield open(self.source, 'rb')


def open_resources(_click_ctx=None, _click_param=None, sources=None):
    """Yields read-only binary fobjs for all given sources.

    Resources with open/connection errors are ignored and warnings are
    logged.

    Designed for use as click option callback.
    """
    if sources:
        for s in sources:
            try:
                with Resource(s).open() as f:
                    yield f
            except (EnvironmentError, urllib.error.URLError) as e:
                _log.warning('failed to open %s: %s', s, e)
