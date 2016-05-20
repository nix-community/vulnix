import yaml


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
        for m in self.MATCHABLE:
            if getattr(self, m):
                break
        else:
            raise ValueError(
                "Whitelist rules must specify at least one of the matchable "
                "attributes: {}".format(', '.join(self.MATCHABLE)))

    def matches(self, other):
        for attr in self.MATCHABLE:
            other_value = getattr(other, attr)
            self_value = getattr(self, attr)
            if other_value and other_value != self_value:
                return False
        return True


class WhiteList(object):

    def __init__(self):
        self.rules = []

    def parse(self, filename='whitelist.yaml'):
        for rule in yaml.load(open(filename, 'r')):
            self.rules.append(WhiteListRule(**rule))

    def __contains__(self, test):
        for rule in self.rules:
            if rule.matches(test):
                return True
        return False
