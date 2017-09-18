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
from .nvd import NVD, DEFAULT_MIRROR, DEFAULT_CACHE_DIR
from .whitelist import WhiteList
from .utils import cve_url
import click
import glob
import logging
import os
import os.path
import pkg_resources
import sys
import time
import urllib.request

DEFAULT_WHITELIST = pkg_resources.resource_filename(
    __name__, 'default_whitelist.yaml')

_log = logging.getLogger(__name__)


class Timer:

    def __init__(self, debugmsg):
        self.debugmsg = debugmsg

    def __enter__(self):
        _log.debug('Starting: ' + self.debugmsg)
        self.start = time.clock()
        return self

    def __exit__(self, *args):
        self.end = time.clock()
        self.interval = self.end - self.start
        _log.debug('Finished: {} took {:.2f} seconds'.format(
                   self.debugmsg, self.interval))


def howto():
    head, tail = __doc__.split('\n', 1)
    click.secho(head, fg='yellow')
    click.echo(tail, nl=False)


def output(affected_derivations, verbosity, notfixed):
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
    if amount == 0:
        summary = 'Found no advisories'
    else:
        names = ', '.join(d.simple_name for d in derivations[:3])
        summary = 'Found {} advisories for {}'.format(amount, names)
        if amount > 3:
            summary += ', ... (and {:d} more)'.format(amount - 3)
    click.secho(summary, fg='red')

    for derivation in derivations:
        if derivation.status == 'inprogress':
            progress = '*'
        elif derivation.status == 'notfixed':
            # Don't show 'notfixed' derivations if not wanted.
            if not notfixed:
                continue
            progress = '!'
        else:
            progress = ''
        click.echo('\n{}\n{}{}\n'.format('=' * 72, derivation.name, progress))
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
        for cve_id in derivation.affected_by:
            click.echo("\t" + cve_url(cve_id))
        status.append(1 if derivation.status == 'inprogress' else 2)

    return max(status)


def populate_store(gc_roots, paths):
    """Load derivations from nix store depending on cmdline invocation."""
    store = Store()
    if gc_roots:
        store.add_gc_roots()
    for path in paths:
        store.add_path(path)
    return store


class Resource:

    def __init__(self, url):
        self.url = url
        if self.url.startswith('http'):
            # http ressource
            try:
                self.fp = urllib.request.urlopen(url)
            except:
                _log.debug("Couldn't open: {}".format(self.url))
        else:
            # local file ressource
            self.fp = open(url)


def open_resource(ctx, param, value):
    """returns fp for files or remote ressources"""
    if value:
        for v in value:
            yield Resource(v)


def run(nvd, update_cache, whitelist, gc_roots, paths, verbose, notfixed):
    with Timer('Load NVD data'):
        nvd.update()
        if update_cache:
            sys.exit(0)

    with Timer('Load derivations'):
        store = populate_store(gc_roots, paths)

    affected = set()
    with Timer('Scan vulnerabilities'):
        for derivation in store.derivations.values():
            with Timer('Scan {}'.format(derivation.name)):
                derivation.check(nvd, whitelist)
                if derivation.is_affected:
                    affected.add(derivation)

    returncode = 0
    if affected:
        # sensu maps following return codes
        # 0 - ok, 1 - warning, 2 - critical, 3 - unknown
        returncode = output(affected, verbose, notfixed)
    else:
        click.secho('vulnix: no vulnerabilities detected', fg='green')
        _log.debug('returncode %d', returncode)


@click.command('vulnix')
@click.option('-S', '--system', is_flag=True,
              help='Scan the current system')
@click.option('-G', '--gc-roots', is_flag=True,
              help='Scan all active GC roots (including old ones)')
@click.option('-w', '--whitelist', multiple=True, callback=open_resource,
              help='Add another whitelist ressource to declare exceptions.')
@click.option('-m', '--mirror',
              help='Mirror to fetch NVD archives from. Default: {}'.format(
                  DEFAULT_MIRROR),
              default=DEFAULT_MIRROR)
@click.option('--default-whitelist/--no-default-whitelist', default=True,
              help='Load built-in base whitelist from "{}". Additional '
              'whitelist files can be specified using the "-w" option. '
              'Default: yes'.format(DEFAULT_WHITELIST))
@click.option('-d', '--debug', is_flag=True,
              help='Show debug information.')
@click.option('-v', '--verbose', count=True,
              help='Increase output verbosity.')
@click.option('-c', '--cache-dir', default=DEFAULT_CACHE_DIR,
              help='Cache directory to store parsed archive data. '
              'Default: {}'.format(DEFAULT_CACHE_DIR))
@click.option('-U', '--update-cache', is_flag=True,
              help='Update the parsed archives and exit')
@click.option('-V', '--version', is_flag=True,
              help='Print vulnix version and exit')
@click.option('--notfixed', is_flag=True, default=False,
              help='Show packages which are not fixed by upstream')
@click.argument('path', nargs=-1,
                type=click.Path(exists=True))
def main(debug, verbose, whitelist, default_whitelist,
         gc_roots, system, path, mirror, cache_dir, update_cache, version,
         notfixed):
    """Scans nix store paths for derivations with security vulnerabilities."""
    if debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.getLogger('requests').setLevel(logging.ERROR)
        if verbose:
            logging.basicConfig(level=logging.INFO)
        else:
            logging.basicConfig(level=logging.WARNING)

    if version:
        print('vulnix ' + pkg_resources.get_distribution('vulnix').version)
        sys.exit(0)

    if not (update_cache or gc_roots or system or path):
        howto()
        sys.exit(3)

    cache_dir = os.path.expanduser(cache_dir)
    _log.info('Using cache in %s', cache_dir)

    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)

    # Clean up old-style data
    for file in glob.glob(cache_dir + '/*.xml*'):
        os.unlink(file)

    paths = list(path)
    if system:
        paths.append('/nix/var/nix/gcroots/current-system')

    with Timer('Load whitelist'):
        wl = WhiteList()
        if default_whitelist:
            with open(DEFAULT_WHITELIST) as f:
                wl.parse(f)
        if whitelist:
            for res in whitelist:
                wl.parse(res.fp)

    nvd = NVD(mirror=mirror, cache_dir=cache_dir)
    with nvd:
        try:
            returncode = run(nvd, update_cache, wl, gc_roots, paths, verbose,
                             notfixed)
        except RuntimeError as e:
            _log.critical(e)
            sys.exit(2)

    # This needs to happen outside the NVD context: otherwise ZODB will abort
    # the transaction and we will keep updating over and over.
    sys.exit(returncode)
