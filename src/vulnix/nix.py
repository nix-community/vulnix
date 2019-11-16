from .derivation import load, SkipDrv
from .utils import call
import os.path as p
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
        _log.debug('loading all live derivations')
        for d in call(['nix-store', '--gc', '--print-live']).splitlines():
            self.update(d)

    def add_path(self, path):
        """Add the closure of all derivations referenced by a store path."""
        if not p.exists(path):
            raise RuntimeError('path `{}` does not exist - cannot load '
                               'derivations referenced from it'.format(path))
        _log.debug('loading derivations referenced by "%s"', path)
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
