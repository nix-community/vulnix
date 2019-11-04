from BTrees import OOBTree
from persistent import Persistent
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

logger = logging.getLogger(__name__)


class NVD(object):
    """Access to the National Vulnerability Database.

    https://nvd.nist.gov/
    """

    has_updates = False

    def __init__(self, mirror=DEFAULT_MIRROR, cache_dir=DEFAULT_CACHE_DIR):
        self.mirror = mirror.rstrip('/') + '/'
        self.cache_dir = p.expanduser(cache_dir)
        # XXX computation missing
        self.relevant_archives = 'modified'

    def __enter__(self):
        logger.debug('Using cache in %s', self.cache_dir)
        os.makedirs(self.cache_dir, exist_ok=True)
        storage = ZODB.FileStorage.FileStorage(
            p.join(self.cache_dir, 'Data.fs'))
        self._db = ZODB.DB(storage)
        self._connection = self._db.open()
        self._root = self._connection.root()
        self._root.setdefault('archive', OOBTree.OOBTree())
        self._root.setdefault('advisory', OOBTree.OOBTree())
        self._root.setdefault('by_product', OOBTree.OOBTree())
        self._root.setdefault('meta', Meta())
        return self

    def __exit__(self, exc_type=None, exc_value=None, exc_tb=None):
        if exc_type is None:
            transaction.commit()
            meta = self._root['meta']
            if self.has_updates:
                meta.pack_counter += 1
                if meta.pack_counter > 25:
                    logger.debug('Packing database')
                    self._db.pack()
                    meta.pack_counter = 0
                transaction.commit()
        else:
            transaction.abort()
        self._connection.close()

    def update(self):
        for a in self.relevant_archives:
            arch = Archive(a)
            arch.download(self.mirror)
            self.add(arch)
            self.has_updates = True
        self.reindex()
        transaction.commit()

    def add(self, archive):
        advisories = self._root['advisory']
        for (cve_id, adv) in archive.items():
            advisories[cve_id] = adv

    def reindex(self):
        del self._root['by_product']
        bp = OOBTree.OOBTree()
        for vuln in self._root['advisory'].values():
            for prod in (n.product for n in vuln.nodes):
                if prod not in bp:
                    bp[prod] = []
                bp[prod].append(vuln)
        self._root['by_product'] = bp

    def by_id(self, cve_id):
        return self._root['advisory'][cve_id]

    def by_product(self, product):
        return self._root['by_product'][product]


class Archive:

    def __init__(self, name):
        self.name = name
        self.download_uri = 'nvdcve-1.1-{}.json.gz'.format(name)
        self.advisories = {}

    def download(self, mirror):
        url = mirror + self.download_uri
        logger.debug('Downloading %s', url)
        req = requests.get(url)
        req.raise_for_status()
        self.parse(gzip.decompress(req.content))

    def parse(self, nvd_json):
        raw = json.loads(nvd_json)
        for item in raw['CVE_Items']:
            try:
                vuln = Vulnerability.parse(item)
                self.advisories[vuln.cve_id] = vuln
            except ValueError:
                logger.debug('failed to parse NVD item: %s', item)

    def items(self):
        return self.advisories.items()


class Vulnerability(Persistent):

    cve_id = None
    nodes = None
    cvss2 = None
    cvss3 = None

    def __init__(self, cve_id, nodes=None, cvss2=None, cvss3=None):
        self.cve_id = cve_id
        self.nodes = nodes or []
        self.cvss2 = cvss2
        self.cvss3 = cvss3

    @classmethod
    def parse(cls, item):
        res = cls(item['cve']['CVE_data_meta']['ID'])
        if 'configurations' in item:
            res.nodes = Node.parse(item['configurations'].get('nodes', {}))
        return res

    def __repr__(self):
        return '<Vulnerability {}>'.format(self.cve_id)

    def __eq__(self, other):
        return (self.cve_id == other.cve_id and
                self.nodes == other.nodes and
                self.cvss2 == other.cvss2 and
                self.cvss3 == other.cvss3)


class Node(Persistent):

    vendor = None
    product = None
    versions = None

    def __init__(self, vendor, product, versions=None):
        self.vendor = vendor
        self.product = product
        self.versions = versions or []

    @classmethod
    def parse(cls, nodes):
        res = []
        for node in nodes:
            res += cls.parse_matches(node.get('cpe_match', []))
            res += cls.parse(node.get('children', []))
        return res

    @classmethod
    def parse_matches(cls, cpe_match):
        nodes = []
        for expr in cpe_match:
            if expr.get('vulnerable') is not True:
                continue
            (cpe, cpevers, typ, vendor, product, vers, rev, _) = \
                expr['cpe23Uri'].split(':', 7)
            if cpe != 'cpe' or cpevers != '2.3' or typ != 'a':
                continue
            e = cls(vendor, product)
            v = e.versions
            if 'versionStartIncluding' in expr:
                v.append('>=' + expr['versionStartIncluding'])
            if 'versionStartExcluding' in expr:
                v.append('>' + expr['versionStartExcluding'])
            if 'versionEndIncluding' in expr:
                v.append('<=' + expr['versionEndIncluding'])
            if 'versionEndExcluding' in expr:
                v.append('<' + expr['versionEndExcluding'])
            if vers and vers != '*' and vers != '-':
                if rev and rev != '*' and rev != '-':
                    vers = vers + '-' + rev
                v.append('=' + vers)
            # no point adding an expr without any version match
            if v:
                nodes.append(e)
        # Check if all (vendor, product) pairs are the same.
        if len(nodes) > 1:
            if (all(nodes[0].vendor == v.vendor for v in nodes[1:]) and
                    all(nodes[0].product == v.product for v in nodes[1:])):
                for v in nodes[1:]:
                    nodes[0].versions.extend(v.versions)
                return [nodes[0]]
        return nodes

    def __eq__(self, other):
        return (self.vendor == other.vendor and
                self.product == other.product and
                self.versions == other.versions)

    def __repr__(self):
        return '<Node {}, {}, {}>'.format(
            self.vendor, self.product, self.versions)


class Meta(Persistent):
    """Metadate for database maintenance control"""
    pack_counter = 0
