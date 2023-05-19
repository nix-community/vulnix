from abc import ABC, abstractmethod
import csv
from datetime import datetime, timedelta
import fcntl
import logging
import os
import os.path as p
import requests
import tempfile

from .nvd import DEFAULT_CACHE_DIR

DEFAULT_KEV_MIRROR = 'https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv'
KEV_FILENAME = 'known_exploited_vulnerabilities.csv'

_log = logging.getLogger(__name__)


class KEVInterface(ABC):

    def is_past_due(self, cve_id):
        """Is due_date() in the past?"""
        return self.is_known_exploited(cve_id) and datetime.strptime(
            self.due_date(cve_id), "%Y-%m-%d") < datetime.now()

    @abstractmethod
    def is_known_exploited(self, cve_id):
        """Is this cve_id known to be under active exploitation?"""
        ...

    @abstractmethod
    def due_date(self, cve_id):
        """By what date does the KVE Catalog say this vulnerability must be mitigated?"""
        ...


class KEV(KEVInterface):
    """Access to the Known Exploited Vulnerabilities Catalog.

    https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    """

    def __init__(self, mirror=DEFAULT_KEV_MIRROR, cache_dir=DEFAULT_CACHE_DIR):
        self.mirror = mirror
        self.cache_dir = p.expanduser(cache_dir)
        self.cache_filename = p.join(self.cache_dir, KEV_FILENAME)

        self._catalog = None

    def is_fresh(self):
        """Is our local cache of the KEV Catalog recent enough?."""
        if not p.exists(self.cache_filename):
            return False
        last_update = datetime.fromtimestamp(
            os.stat(self.cache_filename).st_mtime)
        return last_update > datetime.now() - timedelta(hours=2)

    def update(self):
        """Fetch a fresh copy of the KEV Catalog, if needed."""

        if self.is_fresh():
            return

        _log.info('Loading %s', self.mirror)

        etag = None
        if p.exists(self.cache_filename):
            try:
                etag = os.getxattr(self.cache_filename, "user.ETag")
            except BaseException:
                _log.debug(
                    "Couldn't get ETag xattr.  Oh well.  This is not essential.")

        headers = {'If-None-Match': etag} if etag else {}
        r = requests.get(self.mirror, headers=headers)
        r.raise_for_status()
        if r.status_code == 200:
            with tempfile.NamedTemporaryFile(mode="wb", buffering=0, dir=self.cache_dir, prefix=f"{KEV_FILENAME}.", delete=False) as f:
                f.write(r.content)
                if 'ETag' in r.headers:
                    try:
                        os.setxattr(
                            f.name, "user.ETag", r.headers['ETag'].encode('utf-8'))
                    except BaseException:
                        _log.debug(
                            "Couldn't set ETag xattr.  Oh well.  This is not essential.")
                os.replace(f.name, self.cache_filename)

    def load(self):
        """Read the Known Exploited Vulnerabilities Catalog from local cache."""
        self._catalog = {}
        with open(self.cache_filename) as f:
            reader = csv.DictReader(f)
            for row in reader:
                self._catalog[row["cveID"]] = row["dueDate"]

    def is_known_exploited(self, cve_id):
        if self._catalog is None:
            self.load()
        return cve_id in self._catalog

    def due_date(self, cve_id):
        if self._catalog is None:
            self.load()
        return self._catalog[cve_id]


class FakeKEV(KEVInterface):
    """An in-memory test double for KEV"""

    def __init__(self, data):
        self.data = data

    def is_known_exploited(self, cve_id):
        return cve_id in self.data

    def due_date(self, cve_id):
        return self.data[cve_id]

    def update(self):
        pass
