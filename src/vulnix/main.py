from .nix import Store
from .nvd import NVD
from .whitelist import WhiteList
import click
import argparse
import logging
import time
import sys


class Timer:
    def __enter__(self):
        self.start = time.clock()
        return self

    def __exit__(self, *args):
        self.end = time.clock()
        self.interval = self.end - self.start


def output(affected_derivations, verbosity):
    status = 0
    derivations = []
    seen = {}
    # we need name-version only once
    for item in affected_derivations:
        marker = item.name
        if marker in seen:
            continue
        seen[marker] = 1
        derivations.append(item)
    # sort by name
    derivations.sort(key=lambda k: k.simple_name)
    amount = len(derivations)
    names = ', '.join(derivations[k].simple_name for k in range(3))

    print("Security issues for {}".format(names), end="")
    if amount > 3:
        print(", ... (and {:d} more)".format(amount - 3))

    for derivation in derivations:
        print("=" * 72)
        print(derivation.name)
        print()
        if verbosity >= 1:
            print(derivation.store_path)
            if verbosity >= 2:
                print()
                print("Referenced by:")
                for referrer in derivation.referrers():
                    print("\t" + referrer)
                print("Used by:")
                for root in derivation.roots():
                    print("\t" + root)
        print("CVEs:")
        for cve in derivation.affected_by:
            print("\t" + cve.url)
        print("=" * 72)
        print()

        #  if no status is set, we declare affected derivations as critical
        if status == 0 or status == 1:
            if derivation.status == "inprogress":
                status = 1
        else:
            status = 2

    return status


@click.command('vulnix')
@click.option('-w', '--whitelist',
              help='Add another whiltelist YAML file to define exceptions.')
@click.option('-d', '--debug',
              is_flag=True,
              help='Show debug information.')
@click.option('-v', '--verbose',
              count=True,
              help='Increase output verbosity.')
def main(whitelist, debug, verbose):
    """Scans nix store paths for derivations with security vulnerabilities."""
    logger = logging.getLogger(__name__)

    if debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.getLogger('requests').setLevel(logging.ERROR)
        if verbose:
            logging.basicConfig(level=logging.INFO)
        else:
            logging.basicConfig(level=logging.WARNING)

    store = Store()
    store.update()

    nvd = NVD()
    nvd.update()
    nvd.parse()

    wl = WhiteList()
    wl.parse(filename=whitelist)

    affected = set()

    with Timer() as t:
        for vuln in nvd:
            for prod in vuln.affected_products:
                for derivation in store.product_candidates.get(
                        prod.product, []):
                    derivation.check(vuln, wl)
                    if derivation.is_affected:
                        affected.add(derivation)
    logging.debug('total time: %f', t.interval)

    if affected:
        # sensu maps following return codes
        # 0 - ok, 1 - warning, 2 - critical, 3 - unknown
        return output(affected, verbose)
    else:
        return 0
