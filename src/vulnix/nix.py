from .derivation import load, SkipDrv, Derive
from .utils import call
import os.path as p
import json
import logging

_log = logging.getLogger(__name__)


class Store(object):

    def __init__(self, requisites=True):
        self.requisites = requisites
        self.derivations = set()

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

    def add_path(self, path):
        """Add the closure of all derivations referenced by a store path."""
        if not p.exists(path):
            raise RuntimeError('path `{}` does not exist - cannot load '
                               'derivations referenced from it'.format(path))
        _log.debug('Loading derivations referenced by "%s"', path)
        if path.endswith('.drv'):
            deriver = path
        else:
            deriver = call(['nix-store', '-qd', path]).strip()
            _log.debug('deriver: %s', deriver)
            if not deriver or deriver == 'unknown-deriver':
                raise RuntimeError(
                    'Cannot determine deriver. Is this really a path into the '
                    'nix store?', path)
        if self.requisites:
            for candidate in call(['nix-store', '-qR', deriver]).splitlines():
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
