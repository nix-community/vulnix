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
from .resource import open_resources
from .utils import Timer
from .whitelist import Whitelist
from .output import output
import click
import logging
import pkg_resources
import sys

CURRENT_SYSTEM = '/nix/var/nix/gcroots/current-system'

_log = logging.getLogger(__name__)


def howto():
    head, tail = __doc__.split('\n', 1)
    click.secho(head, fg='yellow')
    click.echo(tail, nl=False)


def init_logging(verbose):
    logging.getLogger('requests').setLevel(logging.ERROR)
    if verbose >= 2:
        logging.basicConfig(level=logging.DEBUG)
    elif verbose >= 1:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARNING)


def populate_store(store, gc_roots, profiles, paths):
    """Load derivations from nix store depending on cmdline invocation."""
    if gc_roots:
        store.add_gc_roots()
    for profile in profiles:
        store.add_profile(profile)
    for path in paths:
        store.add_path(path)
    return store


def run(nvd, store):
    """Returns a dict with affected derivations and vulnerabilities."""
    affected = {}
    for derivation in store.derivations:
        vulns = derivation.check(nvd)
        if vulns:
            affected[derivation] = vulns
    _log.debug("Unfiltered affected: %r", affected)
    return affected


@click.command('vulnix')
# what to scan
@click.option('-S', '--system', is_flag=True,
              help='Scan the current system.')
@click.option('-G', '--gc-roots', is_flag=True,
              help='Scan all active GC roots (including old ones).')
@click.option('-p', '--profile', type=click.Path(exists=True),
              multiple=True, help='Scan this profile (eg: ~/.nix-profile)')
@click.option('-f', '--from-file', type=click.File(mode='r'),
              help='Read derivations from file')
@click.argument('path', nargs=-1, type=click.Path(exists=True))
# modify operation
@click.option('-w', '--whitelist', multiple=True, callback=open_resources,
              help='Load whitelist from file or URL (may be given multiple '
              'times).')
@click.option('-W', '--write-whitelist', type=click.File(mode='a'),
              help='Write TOML whitelist containing current matches.')
@click.option('-c', '--cache-dir', type=click.Path(file_okay=False),
              default=DEFAULT_CACHE_DIR,
              help='Cache directory to store parsed archive data. '
              'Default: {}'.format(DEFAULT_CACHE_DIR))
@click.option('-r/-R', '--requisites/--no-requisites', default=True,
              help='Yes: determine transitive closure. No: examine just the '
              'passed derivations (default: yes).')
@click.option('-C', '--closure', is_flag=True,
              help='Examine the closure of an output path '
              '(runtime dependencies). Implies --no-requisites.')
@click.option('-m', '--mirror',
              help='Mirror to fetch NVD archives from. Default: {}.'.format(
                  DEFAULT_MIRROR),
              default=DEFAULT_MIRROR)
# output control
@click.option('-j', '--json/--no-json', help='JSON vs. human readable output.')
@click.option('-s', '--show-whitelisted', is_flag=True,
              help='Shows whitelisted items as well')
@click.option('-D', '--show-description', is_flag=True,
              help='Show descriptions of vulnerabilities')
@click.option('-v', '--verbose', count=True,
              help='Increase output verbosity (up to 2 times).')
@click.option('-V', '--version', is_flag=True,
              help='Print vulnix version and exit.')
@click.option('--default-whitelist/--no-default-whitelist', default=True,
              help='(obsolete; kept for compatibility reasons)')
@click.option('-F', '--notfixed', is_flag=True,
              help='(obsolete; kept for compatibility reasons)')
def main(verbose, gc_roots, system, from_file, profile, path, mirror,
         cache_dir, requisites, closure, whitelist, write_whitelist,
         version, json, show_whitelisted, show_description,
         default_whitelist, notfixed):
    if version:
        print('vulnix ' + pkg_resources.get_distribution('vulnix').version)
        sys.exit(0)

    if (closure):
        requisites = False

    if not (gc_roots or system or profile or path or from_file):
        howto()
        sys.exit(3)

    init_logging(verbose)

    paths = list(path)
    if system:
        paths.append(CURRENT_SYSTEM)

    try:
        with Timer('Load whitelists'):
            wh_sources = whitelist
            whitelist = Whitelist()
            for wl in wh_sources:
                whitelist.merge(Whitelist.load(wl))
        with Timer('Load derivations'):
            store = Store(requisites, closure)
            if from_file:
                if from_file.name.endswith('.json'):
                    _log.debug("loading packages.json")
                    store.load_pkgs_json(from_file)
                else:
                    for drv in from_file.readlines():
                        paths.append(drv.strip())
            else:
                populate_store(store, gc_roots, profile,  paths)
        with NVD(mirror, cache_dir) as nvd:
            with Timer('Update NVD data'):
                nvd.update()
            with Timer('Scan vulnerabilities'):
                filtered_items = whitelist.filter(run(nvd, store))

            rc = output(
                filtered_items,
                json,
                show_whitelisted,
                show_description,
            )
            if write_whitelist:
                for i in filtered_items:
                    whitelist.add_from(i)
                write_whitelist.close()
                with open(write_whitelist.name, 'w') as f:
                    f.write(str(whitelist))
        sys.exit(rc)

    # This needs to happen outside the NVD context: otherwise ZODB will abort
    # the transaction and we will keep updating over and over.
    except RuntimeError as e:
        _log.exception(e)
        sys.exit(2)
