import json
import re
import functools

from vulnix.utils import call

# see parseDrvName built-in Nix function
# https://nixos.org/nix/manual/#ssec-builtins
R_VERSION = re.compile(r'^(\S+)-([0-9]\S*)$')


class NoVersionError(RuntimeError):

    def __init__(self, drv_name):
        self.drv_name = drv_name


def split_name(fullname):
    """Returns the pure package name and version of a derivation."""
    fullname = fullname.lower()
    if fullname.endswith('.drv'):
        fullname = fullname[:-4]
    m = R_VERSION.match(fullname)
    if m:
        return m.group(1), m.group(2)
    return fullname, None


def load(path):
    with open(path) as f:
        d_obj = eval(f.read(), {'__builtins__': {}, 'Derive': Derive}, {})
    d_obj.store_path = path
    return d_obj


def destructure(env):
    """Decodes Nix 2.0 __structuredAttrs."""
    return json.loads(env['__json'])


@functools.total_ordering
class Derive(object):

    store_path = None

    # This __init__ is compatible with the structure in the derivation file.
    # The derivation files are just accidentally Python-syntax, but hey!
    def __init__(self, _output=None, _inputDrvs=None, _inputSrcs=None,
                 _system=None, _builder=None, _args=None,
                 envVars={}, derivations=None, name=None, affected_by=None):
        envVars = dict(envVars)
        self.name = name or envVars.get('name')
        if not self.name:
            self.name = destructure(envVars)['name']
        self.pname, self.version = split_name(self.name)
        if not self.version:
            raise NoVersionError(self.name)
        self.patches = envVars.get('patches', '')
        self.affected_by = affected_by or set()

    def __repr__(self):
        return '<Derive({}, {})>'.format(
                repr(self.name), repr(self.affected_by))

    def __eq__(self, other):
        if type(self) != type(other):
            return NotImplemented
        return ((self.name, self.version, self.affected_by) ==
                (other.name, other.version, other.affected_by))

    def __lt__(self, other):
        if type(self) != type(other):
            return NotImplemented
        return ((self.name, self.version, self.affected_by) <
                (other.name, other.version, other.affected_by))

    def __gt__(self, other):
        if type(self) != type(other):
            return NotImplemented
        return ((self.name, self.version, self.affected_by) >
                (other.name, other.version, other.affected_by))

    @property
    def is_affected(self):
        return bool(self.affected_by)

    def product_candidates(self):
        return {self.pname, self.pname.replace('-', '_')}

    def check(self, nvd):
        patched_cves = self.patched()
        for prod in self.product_candidates():
            for vuln in nvd.by_product_name(prod):
                for cpe in vuln.affected_products:
                    if not self.matches(cpe):
                        continue
                    if vuln.cve_id not in patched_cves:
                        self.affected_by.add(vuln.cve_id)
                        break

    def matches(self, cpe):
        return self.pname == cpe.product and self.version in cpe.versions

    def roots(self):
        return call(
            ['nix-store', '--query', '--roots', self.store_path]).split('\n')

    def referrers(self):
        return call(['nix-store', '--query', '--referrers',
                     self.store_path]).split('\n')

    R_CVE = re.compile(r'CVE-\d{4}-\d+', flags=re.IGNORECASE)

    def patched(self):
        """Guess which CVEs are patched from patch names."""
        return set(
            m.group(0).upper() for m in self.R_CVE.finditer(self.patches))
