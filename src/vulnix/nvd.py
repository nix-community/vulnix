from BTrees import OOBTree
from datetime import datetime, date, timedelta
from persistent import Persistent
from .vulnerability import Vulnerability
import glob
import gzip
import json
import logging
import os
import os.path as p
import requests
import transaction
import ZODB
import ZODB.FileStorage

DEFAULT_MIRROR = 'https://nvd.nist.gov/feeds/json/cve/1.1/'
DEFAULT_CACHE_DIR = '~/.cache/vulnix'

_log = logging.getLogger(__name__)


class NVD(object):
    """Access to the National Vulnerability Database.

    https://nvd.nist.gov/
    """

    def __init__(self, mirror=DEFAULT_MIRROR, cache_dir=DEFAULT_CACHE_DIR):
        self.mirror = mirror.rstrip('/') + '/'
        self.cache_dir = p.expanduser(cache_dir)
        current = date.today().year
        self.available_archives = [y for y in range(current-5, current+1)]

    def __enter__(self):
        """Keeps database connection open while in this context."""
        _log.debug('Opening database in %s', self.cache_dir)
        os.makedirs(self.cache_dir, exist_ok=True)
        self._db = ZODB.DB(ZODB.FileStorage.FileStorage(
            p.join(self.cache_dir, 'Data.fs')))
        self._connection = self._db.open()
        self._root = self._connection.root()
        try:
            self._root.setdefault('advisory', OOBTree.OOBTree())
            self._root.setdefault('by_product', OOBTree.OOBTree())
            self._root.setdefault('meta', Meta())
            # may trigger exceptions if the database is inconsistent
            list(self._root['by_product'].keys())
            if 'archives' in self._root:
                _log.warn('Pre-1.9.0 database found - rebuilding')
                self.reinit()
        except (TypeError, EOFError):
            _log.warn('Incompatible objects found in database - rebuilding DB')
            self.reinit()
        return self

    def __exit__(self, exc_type=None, exc_value=None, exc_tb=None):
        if exc_type is None:
            if self.meta.should_pack():
                _log.debug('Packing database')
                self._db.pack()
            transaction.commit()
        else:
            transaction.abort()
        self._connection.close()
        self._connection = None
        self._db = None

    def reinit(self):
        """Remove old DB and rebuild it from scratch."""
        self._root = None
        transaction.abort()
        self._connection.close()
        self._db = None
        for f in glob.glob(p.join(self.cache_dir, "Data.fs*")):
            os.unlink(f)
        self._db = ZODB.DB(ZODB.FileStorage.FileStorage(
            p.join(self.cache_dir, 'Data.fs')))
        self._connection = self._db.open()
        self._root = self._connection.root()
        self._root['advisory'] = OOBTree.OOBTree()
        self._root['by_product'] = OOBTree.OOBTree()
        self._root['meta'] = Meta()

    @property
    def meta(self):
        return self._root['meta']

    def relevant_archives(self):
        """Returns list of NVD archives to check.

        If there was an update within the last hour, noting is done. If
        the last update was recent enough to be covered by the
        'modified' feed, only that is checked. Else, all feeds are
        checked.
        """
        last_update = self.meta.last_update
        if last_update > datetime.now() - timedelta(hours=2):
            return []
        # the "modified" feed is sufficient if used frequently enough
        if last_update > datetime.now() - timedelta(days=7):
            return ['modified']
        return self.available_archives

    def update(self):
        """Download archives (if changed) and add CVEs to database."""
        changed = []
        for a in self.relevant_archives():
            arch = Archive(a)
            changed.append(arch.download(self.mirror, self.meta))
            self.add(arch)
        if any(changed):
            self.meta.last_update = datetime.now()
            self.reindex()

    def add(self, archive):
        advisories = self._root['advisory']
        for (cve_id, adv) in archive.items():
            advisories[cve_id] = adv

    def reindex(self):
        """Regenerate product index."""
        _log.info('Reindexing database')
        del self._root['by_product']
        bp = OOBTree.OOBTree()
        for vuln in self._root['advisory'].values():
            if vuln.nodes:
                for prod in (n.product for n in vuln.nodes):
                    bp.setdefault(prod, [])
                    bp[prod].append(vuln)
        self._root['by_product'] = bp
        transaction.commit()

    def by_id(self, cve_id):
        """Returns vuln or raises KeyError."""
        return self._root['advisory'][cve_id]

    def by_product(self, product):
        """Returns list of matching vulns or empty list."""
        try:
            return self._root['by_product'][product]
        except KeyError:
            return []

    def affected(self, pname, version):
        """Returns list of matching vulnerabilities."""
        res = set()
        for vuln in self.by_product(pname):
            if vuln.match(pname, version):
                res.add(vuln)
        return res


class Archive:

    """Single JSON data structure from NIST NVD."""

    def __init__(self, name):
        """Creates JSON feed object.

        `name` consists of a year or "modified".
        """
        self.name = name
        self.download_uri = 'nvdcve-1.1-{}.json.gz'.format(name)
        self.advisories = {}

    def download(self, mirror, meta):
        """Fetches compressed JSON data from NIST.

        Nothing is done if we have already seen the same version of
        the feed before.

        Returns True if anything has been loaded successfully.
        """
        url = mirror + self.download_uri
        _log.info('Loading %s', url)
        r = requests.get(url, headers=meta.headers_for(url))
        r.raise_for_status()
        if r.status_code == 200:
            _log.debug('Loading JSON feed "%s"', self.name)
            self.parse(gzip.decompress(r.content))
            meta.update_headers_for(url, r.headers)
            return True
        else:
            _log.debug('Skipping JSON feed "%s" (%s)', self.name, r.reason)
            return False

    def parse(self, nvd_json):
        added = 0
        raw = json.loads(nvd_json)
        for item in raw['CVE_Items']:
            try:
                vuln = Vulnerability.parse(item)
                self.advisories[vuln.cve_id] = vuln
                added += 1
            except ValueError:
                _log.debug('Failed to parse NVD item: %s', item)
        _log.debug("Added %s vulnerabilities", added)

    def items(self):
        return self.advisories.items()


class Meta(Persistent):
    """Metadate for database maintenance control"""

    pack_counter = 0
    last_update = datetime(1970, 1, 1)
    etag = None

    def should_pack(self):
        self.pack_counter += 1
        if self.pack_counter > 25:
            self.pack_counter = 0
            return True
        return False

    def headers_for(self, url):
        """Returns dict of additional request headers."""
        if self.etag and url in self.etag:
            return {'If-None-Match': self.etag[url]}
        return {}

    def update_headers_for(self, url, resp_headers):
        """Updates self from HTTP response headers."""
        if 'ETag' in resp_headers:
            if self.etag is None:
                self.etag = OOBTree.OOBTree()
            self.etag[url] = resp_headers['ETag']
