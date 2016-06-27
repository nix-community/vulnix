import yaml
import logging

_log = logging.getLogger(__name__)


class WhiteListRule(object):

    MATCHABLE = ['cve', 'name', 'version', 'vendor', 'product']

    def __init__(self, cve=None, name=None, version=None, vendor=None,
                 product=None, comment=None, status='ignore'):
        self.cve = cve
        self.name = name
        self.version = version
        if self.version is not None:
            assert isinstance(version, str)
        self.comment = comment
        self.vendor = vendor
        self.product = product
        assert status in ['ignore', 'inprogress']
        self.status = status
        for m in self.MATCHABLE:
            if getattr(self, m):
                break
        else:
            raise ValueError(
                "Whitelist rules must specify at least one of the matchable "
                "attributes: {}".format(', '.join(self.MATCHABLE)))

    def matches(self, vulnerability, cpe, derivation):
        """A rule matches when a vulnerability/derivation combination
        is whitelisted by this rule.
        """
        if self.cve and vulnerability.cve_id != self.cve:
            return
        if self.name and derivation.simple_name != self.name:
            return
        if self.version and cpe.version != self.version:
            return
        if self.vendor and cpe.vendor != self.vendor:
            return
        if self.product and cpe.product != self.product:
            return
        if self.status == 'inprogress':
            derivation.status = 'inprogress'
            return
        return True


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
        for rule in self.rules:
            if rule.matches(vuln, cpe, derivation):
                return True
        return False
