import datetime
import glob
import gzip
import logging
import os.path
import os
import pickle
import requests
import shutil
import time
import xml.etree.ElementTree as ET

NS = {'': 'http://scap.nist.gov/schema/feed/vulnerability/2.0',
      'vuln': 'http://scap.nist.gov/schema/vulnerability/0.4'}

logger = logging.getLogger(__name__)


class NVD(object):
    """Access to the National Vulnerability Database.

    https://nvd.nist.gov/

    """

    mirror = 'http://static.nvd.nist.gov/feeds/xml/cve/'
    file = 'nvdcve-2.0-{}.xml.gz'

    earliest = datetime.datetime.today().year - 5  # last five years
    updates = 'Modified'

    def __init__(self, mirror=None, cache_dir=None):
        self.cves = {}
        if mirror:
            self.mirror = mirror
        if not cache_dir:
            cache_dir = '~/.cache/vulnix'

        self.source = self.mirror + self.file
        self.download_path = os.path.expanduser(cache_dir) + '/'

        self.by_product_name = {}

    def update(self):
        if not os.path.exists(self.download_path):
            os.makedirs(self.download_path)
        current_year = datetime.datetime.today().year
        years = list(range(self.earliest, current_year + 1)) + [self.updates]
        for year in years:
            target = self.download_path + '{}.xml'.format(year)
            # don't download it again if archive exists
            if os.path.exists(target + '.cached'):
                # XXX except for current year and modified
                # current update regime by NIST is about eight days
                if year == current_year and \
                        self._isolder(target + '.cached', 8):
                    pass
                elif year == self.updates and \
                        self._isolder(target + '.cached', 8):
                    pass
                else:
                    logger.info('{} is up-to-date.'.format(year))
                    continue
            logger.info('Updating {}'.format(year))
            r = requests.get(self.source.format(year))
            r.raise_for_status()
            with open(target + '.gz', 'wb') as fd:
                for chunk in r.iter_content(1024**2):
                    fd.write(chunk)

    def _isolder(self, file, days):
        if os.path.getmtime(file) < time.time() - days * 24 * 3600:
            return True
        else:
            return False

    def _clean(self):
        for file in glob.glob(self.download_path + '*.xml'):
            os.remove(file)
            os.remove(file + '.gz')

    def _unpack(self):
        for archive in glob.glob(self.download_path + '*.xml.gz'):
            with gzip.open(archive, 'rb') as f_in:
                    with open(archive.strip('.gz'), 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)

    def parse(self):
        self._unpack()

        for source in glob.glob(self.download_path + '*.xml'):
            # looking for non-cached vulnerability objects
            if os.path.exists(source):
                self.parse_file(source)
        for cached in glob.glob(self.download_path + '*.cached'):
            with open(cached, 'rb') as fobj:
                for vx in pickle.load(fobj):
                    self.cves[vx.cve_id] = vx
                    for p in vx.affected_products:
                        p_vx = self.by_product_name.setdefault(
                            p.product, set())
                        p_vx.add(vx)

        self._clean()

    def parse_file(self, filename):
        cached_vx = []
        logger.debug("Parsing {}".format(filename))
        tree = ET.parse(filename)
        root = tree.getroot()
        for node in root:
            vx = Vulnerability.from_node(node)
            self.cves[vx.cve_id] = vx
            cached_vx.append(vx)
        # cache results
        with open(filename + '.cached', 'wb') as fobj:
            pickle.dump(cached_vx, fobj)

    def __iter__(self):
        return iter(self.cves.values())


class Vulnerability(object):

    cve_id = None
    affected_products = ()

    def __init__(self):
        self.affected_products = []

    @property
    def url(self):
        return ('https://web.nvd.nist.gov/view/vuln/detail?vulnId={}'.
                format(self.cve_id))

    @staticmethod
    def from_node(node):
        self = Vulnerability()
        self.cve_id = node.get('id')
        for product in node.findall('.//vuln:product', NS):
            cpe = CPE.from_uri(product.text)
            if cpe.product is None:
                # This usually indicates a combination where some vulnerability
                # only applies for a specific operating system *vendor*
                continue
            self.affected_products.append(cpe)
        return self


class CPE(object):

    part = None
    vendor = None
    product = None
    version = None
    update = None
    edition = None
    lang = None

    @staticmethod
    def from_uri(uri):
        self = CPE()
        self.uri = uri
        protocol, identifier = uri.split(':/')
        assert protocol == 'cpe'
        component_list = identifier.split(':')
        components = ['part', 'vendor', 'product', 'version', 'update',
                      'edition', 'lang']
        while component_list:
            component_name = components.pop(0)
            component_value = component_list.pop(0)
            setattr(self, component_name, component_value)
        return self

    def __repr__(self):
        return '<CPE %s>' % self.uri
