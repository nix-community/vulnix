import logging
import toml
import yaml

_log = logging.getLogger(__name__)


class WhitelistItem:
    ANY = object()

    def __init__(self, **kw):
        for field in ['name', 'version', 'issue', 'comment']:
            self.__dict__[field] = kw.pop(field, self.ANY)
        self.cve = set(kw.pop('cve', []))
        kw.pop('status', '')  # compat
        if kw:
            _log.warning('Unrecognized whitelist keys: {}'.format(kw.keys()),
                    str(self))


class Whitelist:

    def __init__(self):
        self.items = []

    @classmethod
    def from_yaml(cls, fobj):
        wl = cls()
        for item in yaml.load(fobj):
            wl.items.append(WhitelistItem(**item))
        return wl

    def __len__(self):
        return len(self.items)

    def __getitem__(self, key):
        return self.items[key]
