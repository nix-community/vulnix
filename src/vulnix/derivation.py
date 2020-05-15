from .utils import compare_versions
import functools
import json
import logging
import re

_log = logging.getLogger(__name__)


class SkipDrv(RuntimeError):
    """This derivation cannot be treated as package."""
    pass


# see parseDrvName built-in Nix function
# https://nixos.org/nix/manual/#ssec-builtins
R_VERSION = re.compile(r'^(\S+?)-([0-9]\S*)$')


def split_name(fullname):
    """Returns the pure package name and version of a derivation."""
    if fullname.endswith('.drv'):
        fullname = fullname[:-4]
    m = R_VERSION.match(fullname)
    if m:
        return m.group(1), m.group(2)
    return fullname, None


def load(path):
    with open(path) as f:
        d_obj = eval(f.read(), {'__builtins__': {}, 'Derive': Derive}, {})
    _log.debug('Loading drv %s', d_obj.name)
    d_obj.store_path = path
    return d_obj


def destructure(env):
    """Decodes Nix 2.0 __structuredAttrs."""
    return json.loads(env['__json'])


IGNORE_EXT = {
    '.tar.gz', '.tar.bz2', '.tar.xz', '.tar.lz', '.tgz', '.zip', '.gem',
    '.patch', '.patch.gz', '.patch.xz', '.diff',
}


@functools.total_ordering
class Derive(object):
    """Nix derivation as found as .drv files in the Nix store."""

    store_path = None

    def __init__(self, _output=None, _inputDrvs=None, _inputSrcs=None,
                 _system=None, builder=None, _args=None,
                 envVars={}, derivations=None, name=None, patches=None):
        """Create a derivation from a .drv file.

        The derivation files are just accidentally Python-syntax, but
        hey! :-)
        """
        envVars = dict(envVars)
        self.name = name or envVars.get('name')
        if not self.name:
            self.name = destructure(envVars)['name']
        for e in IGNORE_EXT:
            if self.name.endswith(e):
                raise SkipDrv()

        self.pname, self.version = split_name(self.name)
        if not self.version:
            raise SkipDrv()
        self.patches = patches or envVars.get('patches', '')

    def __repr__(self):
        return '<Derive({})>'.format(repr(self.name))

    def __eq__(self, other):
        if type(self) != type(other):
            return NotImplementedError()
        return self.name == other.name

    def __hash__(self):
        return hash(self.name)

    def __lt__(self, other):
        if self.pname < other.pname:
            return True
        if self.pname > other.pname:
            return False
        return compare_versions(self.version, other.version) == -1

    def __gt__(self, other):
        if self.pname > other.pname:
            return True
        if self.pname < other.pname:
            return False
        return compare_versions(self.version, other.version) == 1

    def product_candidates(self):
        """Return product name variations in order of preference."""
        underscore = self.pname.replace('-', '_')
        c = [self.pname, underscore, self.pname.lower(), underscore.lower()]
        yield c[0]
        for i in range(1, len(c)):
            if c[i] not in c[0:i]:
                yield c[i]

    def check(self, nvd):
        affected_by = set()
        patched_cves = self.applied_patches()
        for pname in self.product_candidates():
            for vuln in nvd.affected(pname, self.version):
                if vuln.cve_id not in patched_cves:
                    affected_by.add(vuln)
            if affected_by:
                # don't try further product candidates
                return affected_by
        return affected_by

    R_CVE = re.compile(r'CVE-\d{4}-\d+', flags=re.IGNORECASE)

    def applied_patches(self):
        """Guess which CVEs are patched from patch names."""
        return set(
            m.group(0).upper() for m in self.R_CVE.finditer(self.patches))
