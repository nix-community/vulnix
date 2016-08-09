"""Usage: vulnix {--system | PATH [...]}

vulnix is a tool that scan the NixOS store for packages with known
security issues. There are three main modes of operation:


* Is my NixOS system installation affected?

Invoke:  vulnix --system


* Is my project affected?

Invoke after nix-build:  vulnix ./result


See vulnix --help for a full list of options.
"""

from .nix import Store
from .nvd import NVD
from .whitelist import WhiteList
import click
import logging
import pkg_resources
import subprocess
import sys
import time

DEFAULT_WHITELIST = pkg_resources.resource_filename(
    __name__, 'default_whitelist.yaml')

_log = logging.getLogger(__name__)


class Timer:
    def __enter__(self):
        self.start = time.clock()
        return self

    def __exit__(self, *args):
        self.end = time.clock()
        self.interval = self.end - self.start


def howto():
    head, tail = __doc__.split('\n', 1)
    click.secho(head, fg='yellow')
    click.echo(tail, nl=False)


def output(affected_derivations, verbosity):
    status = []
    derivations = []
    seen = {}
    # we need name-version only once
    for item in affected_derivations:
        marker = item.name
        if marker in seen:
            continue
        seen[marker] = 1
        derivations.append(item)
    derivations.sort(key=lambda k: k.simple_name)

    amount = len(derivations)
    names = ', '.join(derivations[k].simple_name for k in range(3))
    summary = 'Found {} advisories for {}'.format(amount, names)
    if amount > 3:
        summary += ', ... (and {:d} more)'.format(amount - 3)
    click.secho(summary, fg='red')

    for derivation in derivations:
        click.echo('\n{}\n{}\n'.format('=' * 72, derivation.name))
        if verbosity >= 1:
            click.echo(derivation.store_path)
            if verbosity >= 2:
                click.echo()
                click.echo("Referenced by:")
                for referrer in derivation.referrers():
                    click.echo("\t" + referrer)
                click.echo("Used by:")
                for root in derivation.roots():
                    click.echo("\t" + root)
        click.echo("CVEs:")
        for cve in derivation.affected_by:
            click.echo("\t" + cve.url)
        click.echo('=' * 72)
        status.append(1 if derivation.status == 'inprogress' else 2)

    return max(status)


def populate_store(gc_roots, system, paths):
    """Load derivations from nix store depending on cmdline invocation."""
    store = Store()
    if gc_roots:
        store.add_gc_roots()
    if system:
        store.add_path('/nix/var/nix/gcroots/current-system')
        store.add_path('/nix/var/nix/gcroots/booted-system')
    if paths:
        for path in paths:
            store.add_path(path)
    return store


@click.command('vulnix')
@click.option('-G', '--gc-roots', is_flag=True,
              help='Scan all active GC roots (including old ones)')
@click.option('-S', '--system', is_flag=True,
              help='Scan both the booted system and the current system')
@click.option('-w', '--whitelist', multiple=True, type=click.File(),
              help='Add another whiltelist YAML file to declare exceptions.')
@click.option('-m', '--mirror',
              help='Use another mirror for downloading the nvd files. '
              'Default: {}'.format(NVD.mirror))
@click.option('--default-whitelist/--no-default-whitelist', default=True,
              help='Load built-in base whitelist from "{}". Additional '
              'whitelist files can be specified using the "-w" option. '
              'Default: yes'.format(DEFAULT_WHITELIST))
@click.option('-d', '--debug', is_flag=True,
              help='Show debug information.')
@click.option('-v', '--verbose', count=True,
              help='Increase output verbosity.')
@click.option('-c', '--cache-dir', default='~/.cache/vulnix',
              help='Alter the default cache directory')
@click.argument('path', nargs=-1,
                type=click.Path(exists=True))
def main(debug, verbose, whitelist, default_whitelist,
         gc_roots, system, path, mirror, cache_dir):
    """Scans nix store paths for derivations with security vulnerabilities."""
    if debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.getLogger('requests').setLevel(logging.ERROR)
        if verbose:
            logging.basicConfig(level=logging.INFO)
        else:
            logging.basicConfig(level=logging.WARNING)

    if not (gc_roots or system or path):
        howto()
        sys.exit(3)

    _log.debug('loading derivations')
    with Timer() as t:
        try:
            store = populate_store(gc_roots, system, path)
        except (subprocess.CalledProcessError, RuntimeError) as e:
            _log.exception(e)
    _log.debug('store load time: %f', t.interval)

    _log.debug('loading NVD data')
    with Timer() as t:
        if mirror:
            nvd = NVD(mirror=mirror, cache_dir=cache_dir)
        else:
            nvd = NVD(cache_dir=cache_dir)
        nvd.update()
        nvd.parse()
    _log.debug('NVD load time: %f', t.interval)

    wl = WhiteList()
    if default_whitelist:
        with open(DEFAULT_WHITELIST) as f:
            wl.parse(f)
    for fobj in whitelist:
        wl.parse(fobj)

    _log.debug('scanning')
    affected = set()
    with Timer() as t:
        for vuln in nvd:
            for prod in vuln.affected_products:
                for derivation in store.product_candidates.get(
                        prod.product, []):
                    derivation.check(vuln, wl)
                    if derivation.is_affected:
                        affected.add(derivation)
    _log.debug('scan time: %f', t.interval)

    if affected:
        # sensu maps following return codes
        # 0 - ok, 1 - warning, 2 - critical, 3 - unknown
        returncode = output(affected, verbose)
        _log.debug('returncode %d', returncode)
        sys.exit(returncode)
    else:
        click.secho('vulnix: no vulnerabilities detected', fg='green')
