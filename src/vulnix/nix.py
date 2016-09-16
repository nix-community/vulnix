import logging
import subprocess
import sys
import tempfile

_log = logging.getLogger(__name__)


def call(cmd):
    """Call `cmd` and swallow stderr iff returncode is 0."""
    with tempfile.TemporaryFile(prefix='stderr') as capture:
        try:
            output = subprocess.check_output(cmd, stderr=capture)
        except subprocess.CalledProcessError:
            capture.seek(0)
            sys.stderr.write(capture.read().decode('ascii', errors='replace'))
            raise
    return output.decode()


class Store(object):

    def __init__(self):
        self.derivations = {}
        self.product_candidates = {}

    def add_gc_roots(self):
        """Add derivations found for all live GC roots.

        Note that this usually includes old system versions.
        """
        _log.debug('loading all live derivations')
        for d in call(['nix-store', '--gc', '--print-live']).splitlines():
            self.update(d)

    def add_path(self, path):
        """Add the closure of all derivations referenced by a store path."""
        _log.debug('loading derivations referenced by "%s"', path)
        deriver = call(['nix-store', '-qd', path]).strip()
        _log.debug('deriver: %s', deriver)
        if not deriver or deriver == 'unknown-deriver':
            raise RuntimeError(
                'Cannot determine deriver. Is this really a path into the '
                'nix store?', path)
        for candidate in call(['nix-store', '-qR', deriver]).splitlines():
            self.update(candidate)

    def update(self, drv_path):
        if not drv_path.endswith('.drv'):
            return
        if drv_path in self.derivations:
            return
        _log.debug('loading %s', drv_path)
        with open(drv_path) as f:
            d_obj = eval(f.read())
        d_obj.store_path = drv_path
        self.derivations[drv_path] = d_obj
        for product_candidate in d_obj.product_candidates:
            refs = self.product_candidates.setdefault(
                product_candidate, [])
            refs.append(d_obj)


class Derive(object):

    store_path = None

    # This __init__ is compatible with the structure in the derivation file.
    # The derivation files are just accidentally Python-syntax, but hey!
    def __init__(self, output, inputDrvs, inputSrcs, system, builder,  # noqa
                 args, envVars, derivations=None):
        self.output = output
        self.inputDrvs = inputDrvs
        self.inputSrcs = inputSrcs
        self.system = system
        self.builder = builder
        self.args = args
        self.envVars = dict(envVars)
        self.name = self.envVars['name']

        self.affected_by = set()
        self.status = None

    @property
    def is_affected(self):
        return bool(self.affected_by)

    @property
    def simple_name(self):
        # XXX This is a simplification of splitting up the derivation name
        # into its original <name>-<version> form. It's probably going to
        # fail at some point, but we'll cross that bridge then.
        return self.name.rsplit('-', 1)[0]

    @property
    def product_candidates(self):
        variation = self.name.split('-')
        while variation:
            yield '-'.join(variation)
            variation.pop()

    def check(self, nvd, whitelist):
        for candidate in self.product_candidates:
            for vuln in nvd.by_product_name.get(candidate, ()):
                for affected_product in vuln.affected_products:
                    if not self.matches(vuln.cve_id, affected_product):
                        continue
                    if (vuln, affected_product, self) in whitelist:
                        continue
                    self.affected_by.add(vuln)
                    break

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

        # We matched the product and think the version is affected.
        return True

    def roots(self):
        return call(
            ['nix-store', '--query', '--roots', self.store_path]).split('\n')

    def referrers(self):
        return call(['nix-store', '--query', '--referrers',
                     self.store_path]).split('\n')
