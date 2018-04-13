from .derivation import load, split_name, NoVersionError
from .utils import call

import logging
import os.path as p

_log = logging.getLogger(__name__)


class Store(object):

    def __init__(self, requisites=True):
        self.requisites = requisites
        self.derivations = {}

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
        if drv_path in self.derivations:
            return
        # quick'n'dirty check if this is a derivation with version
        # load() may fail even if this pre-check succeeds as the derivation's
        # 'name' attribute is the final source of truth
        _pname, version = split_name(p.basename(drv_path)[:-4])
        if not version:
            return
        _log.debug('loading %s', drv_path)
        try:
            drv_obj = load(drv_path)
        except NoVersionError:
            return
        self.derivations[drv_path] = drv_obj
