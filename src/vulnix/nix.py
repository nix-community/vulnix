import subprocess


def call(cmd):
    output = subprocess.check_output(cmd, stderr=subprocess.PIPE)
    output = output.decode('ascii')
    return output


class Store(object):

    def update(self):
        self.derivations = []
        self.product_candidates = {}
        for d in call(['nix-store', '--gc', '--print-live']).split('\n'):
            if not d.endswith('.drv'):
                continue
            d_src = open(d, 'r').read()
            d_obj = eval(d_src)
            d_obj.store_path = d
            self.derivations.append(d_obj)
            for product_candidate in d_obj.product_candidates:
                refs = self.product_candidates.setdefault(
                    product_candidate, [])
                refs.append(d_obj)

    def __iter__(self):
        return iter(self.derivations)


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

        self.affected_by = set()

    @property
    def is_affected(self):
        return bool(self.affected_by)

    @property
    def simple_name(self):
        # XXX This is a simplification of splitting up the derivation name
        # into its original <name>-<version> form. It's probably going to
        # fail at some point, but we'll cross that bridge then.
        return self.name.rsplit('-', 1)[0]

    @property
    def product_candidates(self):
        variation = self.name.split('-')
        while variation:
            yield '-'.join(variation)
            variation.pop()

    def check(self, vuln, whitelist):
        if vuln in self.affected_by:
            return
        for affected_product in vuln.affected_products:
            if not self.matches(vuln.cve_id, affected_product):
                continue
            if (vuln, affected_product, self) in whitelist:
                continue
            self.affected_by.add(vuln)
            break

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

        # We matched the product and think the version is affected.
        return True

    def roots(self):
        return call(
            ['nix-store', '--query', '--roots', self.store_path]).split('\n')

    def referrers(self):
        return call(['nix-store', '--query', '--referrers',
                     self.store_path]).split('\n')
