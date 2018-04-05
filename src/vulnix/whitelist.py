import collections
import datetime
import logging
import urllib.parse
import toml
import yaml

from vulnix.derivation import split_name

_log = logging.getLogger(__name__)


class WhitelistItem:
    """Single whitelist entry.

    Supported fields:
    - name: package name
    - version: package version (only if pname is set)
    - cve: list of CVE ids
    - issue: bug/case ID URL
    - until: this entry will be disabled after the given date (YYYY-MM-DD)
    - comment: free form text
    - status (ignored for compatibility reasons)

    The version field may be empty which means that all versions of the
    given package are affected. The package may be "*" to indicate any
    package. In this case, there must be at least one CVE ID present.

    If there are both package and CVE IDs set, only vulnerable items
    which match both are whitelisted.
    """

    def __init__(self, **kw):
        for field in ['name', 'version']:
            self.__dict__[field] = kw.pop(field, None) or '*'
        self.cve = (kw.pop('cve', []))
        if isinstance(self.cve, list):
            self.cve = set(self.cve)
        else:
            self.cve = set([self.cve])
        for field in ['issue', 'until', 'comment']:
            self.__dict__[field] = kw.pop(field, None)
        if self.issue:
            (scheme, netloc, path) = urllib.parse.urlparse(self.issue)[0:3]
            if not scheme or not netloc or not path:
                raise ValueError('issue must be a valid URL', self.issue)
        if self.until and not (
                isinstance(self.until, datetime.datetime) or
                isinstance(self.until, datetime.date)):
            self.until = datetime.datetime.strptime(
                    self.until, '%Y-%m-%d').date()
        if self.name == '*' and not self.cve:
            raise RuntimeError('either name or CVE must be set', self.__dict__)
        kw.pop('status', '')  # compat
        if kw:
            _log.warning('Unrecognized whitelist keys: {}'.format(kw.keys()),
                    str(self))


class Whitelist:

    def __init__(self):
        self.entries = collections.defaultdict(dict)

    def insert(self, wle):
        self.entries[wle.name][wle.version] = wle

    @classmethod
    def load(cls, fobj):
        content = fobj.read()
        try:
            return cls.load_toml(content)
        except toml.TomlDecodeError as tomlerr:
            try:
                return cls.load_yaml(content)
            except yaml.YAMLError as yamlerr:
                raise RuntimeError(
                    'whitelist seems neither to be valid TOML valid YAML',
                    tomlerr,
                    yamlerr)

    # not yet implemented
    @classmethod
    def load_toml(cls, content):
        wl = cls()
        if isinstance(content, bytes):
            content = content.decode('utf-8')
        for k, v in toml.loads(content).items():
            if len(v.values()) and isinstance(list(v.values())[0], dict):
                raise RuntimeError('malformed section -- forgot quotes?', k)
            pname, version = split_name(k)
            wl.insert(WhitelistItem(name=pname, version=version, **v))
        return wl

    @classmethod
    def load_yaml(cls, content):
        wl = cls()
        for item in yaml.load(content):
            wl.insert(WhitelistItem(**item))
        return wl

    def __len__(self):
        return len(self.entries)

    def __getitem__(self, key):
        return self.entries[key]
