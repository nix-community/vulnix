import subprocess
import xml.etree.ElementTree as ET
from .whitelist import WhiteList

whitelist = WhiteList()


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

        # match = Match(cve_id, self.name, version, cpe.vendor, cpe.product)
        # if match in whitelist:
        #    return False

        # We matched the product and think the version is affected.
        return True

    def roots(self):
        return call(
            ['nix-store', '--query', '--roots', self.store_path]).split('\n')

    def referrers(self):
        return call(['nix-store', '--query', '--referrers',
                     self.store_path]).split('\n')


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


derivations = []
vulnerabilities = []


def parse_db(filename):
    global vulnerabilities
    tree = ET.parse(filename)
    root = tree.getroot()
    for node in root:
        vx = Vulnerability.from_node(node)
        vulnerabilities.append(vx)


def main():
    global derivations, whitelist
    whitelist.parse()

    for d in call(['nix-store', '--gc', '--print-live']).split('\n'):
        if not d.endswith('.drv'):
            continue
        d_src = open(d, 'r').read()
        d_obj = eval(d_src)
        d_obj.store_path = d
        derivations.append(d_obj)

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
