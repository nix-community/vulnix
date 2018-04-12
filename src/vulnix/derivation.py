import re

from vulnix.utils import call

# see parseDrvName built-in Nix function
# https://nixos.org/nix/manual/#ssec-builtins
R_VERSION = re.compile(r'^(\S+)-([0-9]\S*)$')


def split_name(fullname, version=None):
    """Returns the pure package name and version of a derivation.

    If the version is not already known, a bit of guesswork is involved.
    The heuristic is the same as in builtins.parseDrvName.
    """
    if fullname.endswith('.drv'):
        fullname = fullname[0:fullname.rindex('.drv')]
    if version:
        return fullname.replace('-' + version, ''), version
    m = R_VERSION.match(fullname)
    if m:
        return m.group(1), m.group(2)
    # no version
    return fullname, None


def load(path):
    with open(path) as f:
        d_obj = eval(f.read(), {'__builtins__': {}, 'Derive': Derive}, {})
    d_obj.store_path = path
    return d_obj


class Derive(object):

    store_path = None

    # This __init__ is compatible with the structure in the derivation file.
    # The derivation files are just accidentally Python-syntax, but hey!
    def __init__(self, _output=None, _inputDrvs=None, _inputSrcs=None,
                 _system=None, _builder=None, _args=None,
                 envVars={}, derivations=None, name=None, affected_by=None):
        self.envVars = dict(envVars)
        self.name = name or self.envVars['name']
        self.pname, self.version = split_name(self.name)
        self.affected_by = affected_by or set()

    def __repr__(self):
        return '<Derive({}, {}, {})>'.format(
                repr(self.name), repr(self.envVars), repr(self.affected_by))

    @property
    def is_affected(self):
        return bool(self.affected_by)

    def check(self, nvd):
        patched_cves = self.patched()
        for vuln in nvd.by_product_name(self.name):
            for affected_product in vuln.affected_products:
                if not self.matches(vuln.cve_id, affected_product):
                    continue
                if vuln.cve_id not in patched_cves:
                    self.affected_by.add(vuln.cve_id)
                    break

    def matches(self, cve_id, cpe):
        # Step 1: determine product name
        prefix = cpe.product + '-'
        if self.name == cpe.product:
            version = None
        elif self.name.startswith(prefix):
            version = self.name.replace(prefix, '', 1)
            if version not in cpe.versions:
                return False
        else:
            # This product doesn't match at all.
            return False

        # We matched the product and think the version is affected.
        return True

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
            m.group(0).upper() for m in self.R_CVE.finditer(
                self.envVars.get('patches', '')))
