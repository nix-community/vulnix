#!/usr/bin/env python3

import subprocess


# We know we can't be affected, but the data doesn't allow us to specifically
# parse/match this correctly.
WHITELIST = [
    'CVE-2015-3717',     # sqlite on specific ios versions
    'CVE-2015-2503'      # microsoft access, accidentally matching the 'access' derivation
]

class CPE(object):

    part = None
    vendor = None
    product = None
    version = None
    update = None
    edition = None
    lang = None

    @staticmethod
    def fromURI(uri):
        self = CPE()
        self.uri = uri
        protocol, identifier = uri.split(':/')
        assert protocol == 'cpe'
        component_list = identifier.split(':')
        components = ['part', 'vendor', 'product', 'version', 'update', 'edition', 'lang']
        while component_list:
            component_name = components.pop(0)
            component_value = component_list.pop(0)
            setattr(self, component_name, component_value)
        return self

    def __repr__(self):
        return '<CPE %s>' % self.uri


class Derive(object):
    
    store_path = None

    def __init__(self, output, inputDrvs, inputSrcs, system, builder, args, envVars):
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
                if self.matches(affected_product):
                    self.affected_by.append(vuln)

    def matches(self, cpe):
        # Is this the right product?
        if self.name == cpe.product:
            # We don't have any version information on the installed package.
            # Assume we're affected and let a human decide.
            return True

        prefix = cpe.product + '-'
        if not self.name.startswith(prefix):
            return False

        # False negatives? How do we protect against those? I.e. if the
        # installed version says "beta" or something which is not or
        # differently represented in the name or vice versa?

        # Lets see whether the remainder is a valid version for this cpe
        suffix = self.name.replace(prefix, '', 1)
        if cpe.version and cpe.version != suffix:
            # We have a version but it doesn't match.
            return False

        # We matched the product and think the version is affected.
        return True

    def roots(self):
        return subprocess.check_output(['nix-store', '--query', '--roots', self.store_path]).decode('ascii').split('\n')

    def referrers(self):
        return subprocess.check_output(['nix-store', '--query', '--referrers', self.store_path]).decode('ascii').split('\n')

derivations = []
for d in subprocess.check_output(['nix-store', '--gc', '--print-live']).decode('ascii').split('\n'):
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
      return 'https://web.nvd.nist.gov/view/vuln/detail?vulnId={}'.format(self.cve_id)

    @staticmethod
    def fromNode(node):
        self = Vulnerability()
        self.cve_id = node.get('id')
        for product in node.findall('.//vuln:product', NS):
            cpe = CPE.fromURI(product.text)
            assert cpe.product is not None
            self.affected_products.append(cpe)
        return self


import xml.etree.ElementTree as ET
NS = {'': 'http://scap.nist.gov/schema/feed/vulnerability/2.0',
      'vuln': 'http://scap.nist.gov/schema/vulnerability/0.4'}

vulnerabilities = []

def parse_db(filename):
  tree = ET.parse(filename)
  root = tree.getroot()
  for node in root:
      vx = Vulnerability.fromNode(node)
      if vx.cve_id in WHITELIST:
          continue
      vulnerabilities.append(vx)

parse_db('nvdcve-2.0-2016.xml')
parse_db('nvdcve-2.0-2015.xml')

for derivation in derivations:
    derivation.check()
    if derivation.is_affected:
        print("="*72)
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
        print("="*72)
        print()
