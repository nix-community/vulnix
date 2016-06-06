from .nix import Store
from .nvd import NVD
from .whitelist import WhiteList
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


def get_args():
    ap = argparse.ArgumentParser(
        prog="vulnix",
        description="scans the active gc-roots for security vulnerabilites")
    ap.add_argument(
        "-d", "--debug", action="store_true",
        help="shows debug information")
    ap.add_argument(
        "-w", "--whitelist",
        help="points toward another whitelist")

    return ap.parse_args()


def output(affected_derivations):
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
    names = ', '.join([k.simple_name for k in derivations])

    print("Security issues for {}".format(names[:3]), end="")
    if amount > 3:
        print(", ... (and {:d} more)".format(amount - 3))

    for derivation in derivations:
        print("=" * 72)
        print(derivation.name)
        print()
        print(derivation.store_path)
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

        if derivation.status and derivation.status == "inprogress":
            status = 1


def main():
    args = get_args()

    logging.basicConfig(level=logging.DEBUG)

    store = Store()
    store.update()

    nvd = NVD()
    nvd.update()
    nvd.parse()

    whitelist = WhiteList()
    whitelist.parse(filename=args.whitelist)

    affected = set()

    with Timer() as t:
        for vuln in nvd:
            for prod in vuln.affected_products:
                for derivation in store.product_candidates.get(
                        prod.product, []):
                    derivation.check(vuln, whitelist)
                    if derivation.is_affected:
                        affected.add(derivation)

    # sensu maps following return codes
    # 0 - ok, 1 - Warning, 2 - critical, 3 - unknown
    status = 0
    if affected:
        status = output(affected)
    else:
        print("ok. No security issues found.")

    if args.debug:
        print(t.interval)
        import pdb
        pdb.set_trace()

    sys.exit(status)
