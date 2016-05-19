#!/usr/bin/env python3

import subprocess
import xml.etree.ElementTree as ET
import yaml


class WhiteListRule(object):

    MATCHABLE = ['cve', 'name', 'version', 'vendor', 'product']

    def __init__(self, cve=None, name=None, version=None, vendor=None,
                 product=None, comment=None, status='ignore'):
        self.cve = cve
        self.name = name
        self.version = version
        self.comment = comment
        self.vendor = vendor
        self.product = product
        assert status in ['ignore', 'inprogress']
        for m in self.MATCHABLE:
            if getattr(self, m):
                break
        else:
            raise ValueError(
                "Whitelist rules must specify at least one of the matchable "
                "attributes: {}".format(', '.join(self.MATCHABLE)))

    def matches(self, other):
        for attr in self.MATCHABLE:
            other_value = getattr(other, attr)
            self_value = getattr(self, attr)
            if other_value and other_value != self_value:
                return False
        return True


class WhiteList(object):

    def parse(self, filename='whitelist.cfg'):
        self.data = []
        for rule in yaml.load(open(filename, 'r')):
            self.data.append(WhiteListRule(**rule))

    def __contains__(self, test):
        for rule in self.data:
            if rule.matches(test):
                return True
        return False


whitelist = WhiteList()
whitelist.parse()


def call(cmd):
    output = subprocess.check_output(cmd, stderr=subprocess.PIPE)
    output = output.decode('ascii')
    return output


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


class Match(object):

    def __init__(self, vulnerability, derivation,
                 version=None, cpe,
                 product=None, comment=None, status='ignore'):
        self.cve =


class Derive(object):

    store_path = None

    # This __init__ is compatible with the structure in the derivation file.
    # The derivation files are just accidentally Python-syntax, but hey!
    def __init__(self, output, inputDrvs, inputSrcs, system, builder,  # noqa
                 args, envVars):
        self.output = output
        self.inputDrvs = inputDrvs
        self.inputSrcs = inputSrcs
        self.system = system
        self.builder = builder
        self.args = args
        self.envVars = dict(envVars)
        self.name = self.envVars['name']

        self.affected_by = []

    @property
    def is_affected(self):
        return bool(self.affected_by)

    def check(self):
        for vuln in vulnerabilities:
            for affected_product in vuln.affected_products:
                if self.matches(vuln.cve_id, affected_product):
                    self.affected_by.append(vuln)

    def matches(self, cve_id, cpe):
        # Step 1: determine product name
        prefix = cpe.product + '-'
        if self.name == cpe.product:
            version = None
        elif self.name.startswith(prefix):
            version = self.name.replace(prefix, '', 1)
            if version != cpe.version:
                return False
        else:
            # This product doesn't match at all.
            return False

        # This is an optimization: reduce the database size and thus search
        # load from CVEs we do not

        if Match(cve_id, self.name, version, cpe.vendor, cpe.product) in whitelist:
            continue

        # We matched the product and think the version is affected.
        return True

    def roots(self):
        return call(
            ['nix-store', '--query', '--roots', self.store_path]).split('\n')

    def referrers(self):
        return call(['nix-store', '--query', '--referrers',
                     self.store_path]).split('\n')

derivations = []
for d in call(['nix-store', '--gc', '--print-live']).split('\n'):
    if not d.endswith('.drv'):
        continue
    d_src = open(d, 'r').read()
    d_obj = eval(d_src)
    d_obj.store_path = d
    derivations.append(d_obj)


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
            assert cpe.product is not None
            self.affected_products.append(cpe)
        return self


NS = {'': 'http://scap.nist.gov/schema/feed/vulnerability/2.0',
      'vuln': 'http://scap.nist.gov/schema/vulnerability/0.4'}

vulnerabilities = []


def parse_db(filename):
    tree = ET.parse(filename)
    root = tree.getroot()
    for node in root:
        vx = Vulnerability.from_node(node)
        vulnerabilities.append(vx)

parse_db('nvdcve-2.0-2016.xml')
parse_db('nvdcve-2.0-2015.xml')


for derivation in derivations:
    derivation.check()
    if derivation.is_affected:
        print("=" * 72)
        print(derivation.name)
        print()
        print(derivation.store_path)
        print()
        print("Referenced by:")
        for referrer in derivation.referrers():
            print("\t" + referrer)
        print("Used by:")
        for root in derivation.roots():
            print("\t" + root)
        print("CVEs:")
        for cve in derivation.affected_by:
            print("\t" + cve.url)
        print("=" * 72)
        print()
