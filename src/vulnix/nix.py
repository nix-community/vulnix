from .derivation import load, SkipDrv, Derive
from .utils import call
import os.path as p
import json
import logging

_log = logging.getLogger(__name__)


class Store(object):

    def __init__(self, requisites=True, closure=False):
        self.requisites = requisites
        self.closure = closure
        self.derivations = set()
        self.experimental_flag_needed = None

    def add_gc_roots(self):
        """Add derivations found for all live GC roots.

        Note that this usually includes old system versions.
        """
        _log.debug('Loading all live derivations')
        for d in call(['nix-store', '--gc', '--print-live']).splitlines():
            self.update(d)

    def add_profile(self, profile):
        """Add derivations found in this nix profile."""
        json_manifest_path = p.join(profile, 'manifest.json')
        if p.exists(json_manifest_path):
            _log.debug('Loading derivations from {}'.format(
                json_manifest_path))
            with open(json_manifest_path, 'r') as f:
                json_manifest = json.load(f)
            if json_manifest['version'] > 1:
                raise RuntimeError(
                    ('Profile manifest.json version {} ' +
                     'not yet supported').format(
                        json_manifest['version']))
            for element in json_manifest['elements']:
                if element['active']:
                    for path in element['storePaths']:
                        self.add_path(path)
        else:
            _log.debug('Loading derivations from user profile {}'.format(
                profile))
            for line in call(['nix-env', '-q', '--out-path',
                              '--profile', profile]).splitlines():
                self.add_path(line.split()[1])

    def _call_nix(self, args):
        if self.experimental_flag_needed is None:
            self.experimental_flag_needed = (
                '--experimental-features' in call(['nix', '--help']))

        if self.experimental_flag_needed:
            return call(['nix',
                         '--experimental-features',
                         'nix-command'] + args)
        return call(['nix'] + args)

    def _find_deriver(self, path, qpi_deriver=None):
        if path.endswith('.drv'):
            return path
        # Deriver from QueryPathInfo
        if qpi_deriver is None:
            qpi_deriver = call(['nix-store', '-qd', path]).strip()
        _log.debug('qpi_deriver: %s', qpi_deriver)
        if qpi_deriver and qpi_deriver != 'unknown-deriver' and p.exists(
                qpi_deriver):
            return qpi_deriver
        # Deriver from QueryValidDerivers
        qvd_deriver = list(json.loads(
            self._call_nix(['show-derivation', path])).keys())[0]
        _log.debug('qvd_deriver: %s', qvd_deriver)
        if qvd_deriver and p.exists(qvd_deriver):
            return qvd_deriver

        error = ""
        if qpi_deriver and qpi_deriver != 'unknown-deriver':
            error += 'Deriver `{}` does not exist.  '.format(qpi_deriver)
        if qvd_deriver and qvd_deriver != qpi_deriver:
            error += 'Deriver `{}` does not exist.  '.format(qvd_deriver)
        if error:
            raise RuntimeError(
                error + "Couldn't find deriver for path `{}`".format(path))
        raise RuntimeError(
            'Cannot determine deriver. Is this really a path into the '
            'nix store?', path)

    def _find_outputs(self, path):
        if not path.endswith('.drv'):
            return [path]

        result = []
        for drv in json.loads(
            self._call_nix(['show-derivation', path])
        ).values():
            for output in drv.get('outputs').values():
                result.append(output.get('path'))
        return result

    def add_path(self, path):
        """Add the closure of all derivations referenced by a store path."""
        if not p.exists(path):
            raise RuntimeError('path `{}` does not exist - cannot load '
                               'derivations referenced from it'.format(path))
        _log.debug('Loading derivations referenced by "%s"', path)

        if self.closure:
            for output in self._find_outputs(path):
                for candidate in map(
                    # We cannot use the `deriver` field directly because
                    # like from `nix-store -qd` that path may not exist.
                    # However, we know that if it is not present
                    # the path has no deriver because it is a
                    # derivation input source so we can skip it.
                    lambda p: self._find_deriver(
                                  p.get('path'),
                                  qpi_deriver=p.get('deriver')
                              ) if p.get('deriver') is not None else None,
                    json.loads(
                        self._call_nix(['path-info', '-r', '--json', output])
                    )
                ):
                    if candidate is not None:
                        self.update(candidate)
        else:
            deriver = self._find_deriver(path)
            if self.requisites:
                for candidate in call([
                    'nix-store', '-qR', deriver
                ]).splitlines():
                    self.update(candidate)
            else:
                self.update(deriver)

    def update(self, drv_path):
        if not drv_path.endswith('.drv'):
            return
        try:
            drv_obj = load(drv_path)
        except SkipDrv:
            return
        self.derivations.add(drv_obj)

    def load_pkgs_json(self, json_fobj):
        for pkg in json.load(json_fobj).values():
            try:
                patches = pkg['patches']
                if 'known_vulnerabilities' in pkg:
                    patches.extend(pkg['known_vulnerabilities'])
                self.derivations.add(Derive(
                    name=pkg['name'], patches=' '.join(patches)))
            except SkipDrv:
                _log.debug("skipping: {}", pkg)
                continue
