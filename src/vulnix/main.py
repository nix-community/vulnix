from .nix import Store
from .nvd import NVD
from .whitelist import WhiteList
import logging
import time


class Timer:
    def __enter__(self):
        self.start = time.clock()
        return self

    def __exit__(self, *args):
        self.end = time.clock()
        self.interval = self.end - self.start


def main():
    logging.basicConfig(level=logging.DEBUG)

    store = Store()
    store.update()

    nvd = NVD()
    nvd.update()
    nvd.parse()

    whitelist = WhiteList()
    whitelist.parse()

    affected = set()

    total = 0
    checked = 0
    with Timer() as t:
        for vuln in nvd:
            for prod in vuln.affected_products:
                for derivation in store.product_candidates.get(
                        prod.product, []):
                    derivation.check(vuln, whitelist)
                    if derivation.is_affected:
                        affected.add(derivation)
    print(total, checked)
    print(t.interval)

    for derivation in affected:
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
