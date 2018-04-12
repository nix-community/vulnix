import collections
import datetime
import logging
import urllib.parse
import toml
import yaml

from vulnix.derivation import split_name

_log = logging.getLogger(__name__)


MATCH_PERM = 'permanent'
MATCH_TEMP = 'temporary'


class WhitelistItem:
    """Single whitelist entry.

    Supported fields:
    - pname: package name or `*` for any package
    - version: package version (only if pname is set)
    - cve: list of CVE ids
    - issue_url: bug/case ID URL
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
        for field in ['pname', 'version']:
            self.__dict__[field] = kw.pop(field, None) or '*'
        self.cve = (kw.pop('cve', []))
        if isinstance(self.cve, list):
            self.cve = set(self.cve)
        else:
            self.cve = set([self.cve])
        for field in ['issue_url', 'until', 'comment']:
            self.__dict__[field] = kw.pop(field, None)
        if self.issue_url:
            (scheme, netloc, path) = urllib.parse.urlparse(self.issue_url)[0:3]
            if not scheme or not netloc or not path:
                raise ValueError('issue must be a valid URL', self.issue_url)
        if self.until and not (
                isinstance(self.until, datetime.datetime) or
                isinstance(self.until, datetime.date)):
            self.until = datetime.datetime.strptime(
                    self.until, '%Y-%m-%d').date()
        if self.pname == '*' and not self.cve:
            raise RuntimeError('either pname or CVE must be set', self.__dict__)
        kw.pop('status', '')  # compat
        if kw:
            _log.warning('Unrecognized whitelist keys: {}'.format(kw.keys()),
                    str(self))

    def covers(self, deriv):
        """Is the given derivation covered by this whitelist item?

        If so, a tuple (match type, whitelist item) is returned.
        """
        if self.pname != '*' and self.pname != deriv.pname:
            return None
        if self.version != '*' and self.version != deriv.version:
            return None
        if self.cve and not self.cve >= deriv.affected_by:
            return None
        if self.until:
            if self.until <= datetime.date.today():
                return None
            else:
                return (MATCH_TEMP, self)
        return (MATCH_PERM, self)


class Masked:

    def __init__(self, derivation, matchtype, whitelist_item):
        self.deriv = derivation
        self.matchtype = matchtype
        self.wli = whitelist_item


class Whitelist:

    def __init__(self):
        self.entries = collections.defaultdict(dict)

    def insert(self, wle):
        self.entries[wle.pname][wle.version] = wle

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

    @classmethod
    def load_toml(cls, content):
        wl = cls()
        if isinstance(content, bytes):
            content = content.decode('utf-8')
        for k, v in toml.loads(content).items():
            if len(v.values()) and isinstance(list(v.values())[0], dict):
                raise RuntimeError('malformed section -- forgot quotes?', k)
            pname, version = split_name(k)
            wl.insert(WhitelistItem(pname=pname, version=version, **v))
        return wl

    @classmethod
    def load_yaml(cls, content):
        wl = cls()
        for item in yaml.load(content):
            pname = item.pop('name', None)
            wl.insert(WhitelistItem(pname=pname, **item))
        return wl

    def __len__(self):
        return len(self.entries)

    def __getitem__(self, key):
        return self.entries[key]

    def candidates(self, pname, version):
        try:
            yield self.entries[pname][version]
        except KeyError:
            pass
        try:
            yield self.entries[pname]['*']
        except KeyError:
            pass
        try:
            yield self.entries['*']['*']
        except KeyError:
            pass

    def find(self, deriv):
        """Finds most specific matching whitelist rule.

        Tries all relevant rules in turn. If a rule matches, a `Masked`
        object is returned. Returns None otherwise.
        """
        for item in self.candidates(deriv.pname, deriv.version):
            match = item.covers(deriv)
            if match:
                return Masked(deriv, match[0], match[1])

    def filter(self, derivations):
        """Splits a list of derivations into (unmasked, masked).

        Masked derivations are those with at least one matching
        whitelist rule. They are returned as `Masked` objects. In case
        of multiple matching rules, the most specific (pname/version) is
        selected. Unmasked derivations, e.g. those without any matching
        whitelist rules, are returned unmodified.
        """
        unmasked, masked = [], []
        for deriv in derivations:
            m = self.find(deriv)
            if m:
                masked.append(m)
            else:
                unmasked.append(deriv)
        return unmasked, masked
