from .nvd import NVD
from .whitelist import WhiteList
import subprocess
import logging

whitelist = WhiteList()


def call(cmd):
    output = subprocess.check_output(cmd, stderr=subprocess.PIPE)
    output = output.decode('ascii')
    return output


class Derive(object):

    store_path = None

    # This __init__ is compatible with the structure in the derivation file.
    # The derivation files are just accidentally Python-syntax, but hey!
    def __init__(self, output, inputDrvs, inputSrcs, system, builder,  # noqa
                 args, envVars):
        self.output = output
        self.inputDrvs = inputDrvs
        self.inputSrcs = inputSrcs
        self.system = system
        self.builder = builder
        self.args = args
        self.envVars = dict(envVars)
        self.name = self.envVars['name']

        self.affected_by = []

    @property
    def is_affected(self):
        return bool(self.affected_by)

    def check(self):
        for vuln in nvd:
            for affected_product in vuln.affected_products:
                if self.matches(vuln.cve_id, affected_product):
                    self.affected_by.append(vuln)

    def matches(self, cve_id, cpe):
        # Step 1: determine product name
        prefix = cpe.product + '-'
        if self.name == cpe.product:
            version = None
        elif self.name.startswith(prefix):
            version = self.name.replace(prefix, '', 1)
            if version != cpe.version:
                return False
        else:
            # This product doesn't match at all.
            return False

        # This is an optimization: reduce the database size and thus search
        # load from CVEs we do not

        # match = Match(cve_id, self.name, version, cpe.vendor, cpe.product)
        # if match in whitelist:
        #    return False

        # We matched the product and think the version is affected.
        return True

    def roots(self):
        return call(
            ['nix-store', '--query', '--roots', self.store_path]).split('\n')

    def referrers(self):
        return call(['nix-store', '--query', '--referrers',
                     self.store_path]).split('\n')


derivations = []
nvd = NVD()


def main():
    logging.basicConfig(level=logging.DEBUG)

    global derivations, whitelist
    whitelist.parse()

    for d in call(['nix-store', '--gc', '--print-live']).split('\n'):
        if not d.endswith('.drv'):
            continue
        d_src = open(d, 'r').read()
        d_obj = eval(d_src)
        d_obj.store_path = d
        derivations.append(d_obj)

    nvd.update()
    nvd.parse()

    for derivation in derivations:
        derivation.check()
        if derivation.is_affected:
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
