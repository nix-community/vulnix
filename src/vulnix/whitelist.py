import datetime
import logging
import re
import toml
import urllib.parse
import yaml

from vulnix.derivation import split_name

_log = logging.getLogger(__name__)


MATCH_PERM = 'permanent'
MATCH_TEMP = 'temporary'


class WhitelistRule:
    """Single whitelist entry.

    Supported fields:
    - pname: package name or `*` for any package
    - version: package version (only if pname is set)
    - cve: affected by CVEs (multi-valued, set)
    - until: this entry will be disabled after the given date (YYYY-MM-DD)
    - issue_url: bug/case ID URLs (multi-valued, set)
    - comment: free form text (multi-valued, list)
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
        for field in ['cve', 'issue_url']:
            v = kw.pop(field, [])
            self.__dict__[field] = set(v) if isinstance(v, list) else set([v])
        if self.pname == '*' and not self.cve:
            raise RuntimeError('either pname or CVE must be set', kw)
        for url in self.issue_url:
            scheme, netloc, path = urllib.parse.urlparse(url)[0:3]
            if not scheme or not netloc or not path:
                raise ValueError('issue must be a valid URL', url)
        v = kw.pop('comment', [])
        self.comment = v if isinstance(v, list) else [v]
        self.until = None
        if 'until' in kw:
            if not (isinstance(kw['until'], datetime.datetime) or
                    isinstance(kw['until'], datetime.date)):
                self.until = datetime.datetime.strptime(
                    kw.pop('until'), '%Y-%m-%d').date()
            else:
                self.until = kw.pop('until')
        kw.pop('status', '')  # compat
        if kw:
            _log.warning('Unrecognized whitelist keys: {}'.format(kw.keys()))

    @property
    def name(self):
        if self.version == '*':
            return self.pname
        return '{}-{}'.format(self.pname, self.version)

    def update(self, other):
        if self.pname != other.pname or self.version != other.version:
            raise RuntimeError(
                'cannot merge rules for different packages', self, other)
        self.cve.update(other.cve)
        if other.until:
            if not self.until or (self.until and other.until > self.until):
                self.until = other.until
        self.issue_url.update(other.issue_url)
        self.comment.extend(other.comment)

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

    def __init__(self, derivation, matchtype, whitelist_rule):
        self.deriv = derivation
        self.matchtype = matchtype
        self.rule = whitelist_rule


class Whitelist:

    def __init__(self):
        self.entries = {}

    def __len__(self):
        return len(self.entries)

    def __getitem__(self, key):
        return self.entries[key]

    def insert(self, rule):
        self.entries[rule.name] = rule

    TOML_SECTION_START = re.compile(r'^\[.*\]', re.MULTILINE)
    YAML_SECTION_START = re.compile(r'^-', re.MULTILINE)

    @classmethod
    def load(cls, fobj):
        """Loads whitelist from file-like object.

        The format (TOML or YAML) is guessed using a heuristic.
        """
        content = fobj.read()
        if isinstance(content, bytes):
            content = content.decode('utf-8')
        name = ''
        if hasattr(fobj, 'name') and fobj.name:
            name = fobj.name
        elif hasattr(fobj, 'geturl'):
            name = fobj.geturl()
        if name.endswith('.toml'):
            return cls.load_toml(content)
        if name.endswith('.yaml'):
            return cls.load_yaml(content)
        if cls.TOML_SECTION_START.search(content):
            return cls.load_toml(content)
        if cls.YAML_SECTION_START.search(content):
            return cls.load_yaml(content)
        raise RuntimeError('cannot detect whitelist format')

    @classmethod
    def load_toml(cls, content):
        wl = cls()
        for k, v in toml.loads(content).items():
            if len(v.values()) and isinstance(list(v.values())[0], dict):
                raise RuntimeError('malformed section -- forgot quotes?', k)
            pname, version = split_name(k)
            wl.insert(WhitelistRule(pname=pname, version=version, **v))
        return wl

    @classmethod
    def load_yaml(cls, content):
        wl = cls()
        for item in yaml.load(content):
            pname = item.pop('name', None)
            wl.insert(WhitelistRule(pname=pname, **item))
        return wl

    def candidates(self, pname, version):
        try:
            yield self.entries['{}-{}'.format(pname, version)]
        except KeyError:
            pass
        try:
            yield self.entries[pname]
        except KeyError:
            pass
        try:
            yield self.entries['*']
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

    def merge(self, other):
        for pkg, rule in other.entries.items():
            if pkg in self.entries:
                self.entries[pkg].update(rule)
            else:
                self.entries[pkg] = rule
