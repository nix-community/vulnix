import yaml
import logging

_log = logging.getLogger(__name__)


class WhiteListRule(object):

    MATCHABLE = ['cve', 'name', 'version', 'vendor', 'product']
    version = None
    status = None

    def __init__(self, cve=None, name=None, version=None, vendor=None,
                 product=None, comment=None, status='ignore'):
        self.cve = cve
        self.name = name
        self.comment = comment
        self.vendor = vendor
        self.product = product
        if version is not None and not isinstance(version, str):
            raise RuntimeError(
                '{}: version must be a string (try quotes)'.format(self))
        self.version = version
        if status not in ['ignore', 'inprogress', 'notfixed']:
            raise RuntimeError(
                '{}: status must be one of ignore, inprogress, notfixed'.
                format(self))
        self.status = status
        if not any((getattr(self, m) for m in self.MATCHABLE)):
            raise RuntimeError(
                "Whitelist rules must specify at least one of the matchable "
                "attributes {}: {}/{}".format(
                    ', '.join(self.MATCHABLE), comment, status))

    def matches(self, vulnerability, cpe, derivation):
        """A rule matches when a vulnerability/derivation combination
        is whitelisted by this rule.
        """
        if self.cve and vulnerability.cve_id != self.cve:
            return False
        if self.name and derivation.pname != self.name:
            return False
        if self.version and derivation.version != self.version:
            return False
        if self.vendor and cpe.vendor != self.vendor:
            return False
        if self.product and cpe.product != self.product:
            return False
# XXX WTF?!?
        if self.status in ('inprogress', 'notfixed'):
            derivation.status = self.status
            return
        return True

    def __str__(self):
        base = '-'.join(filter(None, [self.vendor, self.product, self.name,
                                      self.version]))
        if not base and self.cve:
            return self.cve
        elif self.cve:
            return '{} ({})'.format(base, self.cve)
        return base


class WhiteList(object):

    def __init__(self):
        self.rules = []

    def parse(self, fobj):
        """Extends whitelist with rules read from fobj."""
        prep_rules = []

        if hasattr(fobj, 'name'):
            _log.debug('reading whitelist from %s', fobj.name)

        whitelist = yaml.load(fobj)
        for line in whitelist:
            # special case: use cve key for more than one cve
            if 'cve' in line.keys() and type(line['cve']) == list:
                for cve_id in line['cve']:
                    prep_rules.append(dict(**line))
                    prep_rules[-1]['cve'] = cve_id
            else:
                prep_rules.append(line)
        for rule in prep_rules:
            self.rules.append(WhiteListRule(**rule))

    def __contains__(self, spec):
        (vuln, cpe, derivation) = spec
        return any(rule.matches(vuln, cpe, derivation) for rule in self.rules)
