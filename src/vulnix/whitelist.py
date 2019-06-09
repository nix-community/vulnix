import collections
import datetime
import logging
import re
import toml
import urllib.parse
import yaml

from vulnix.derivation import split_name
from vulnix.output import Filtered

_log = logging.getLogger(__name__)


# brackets must be followed/preceded immediately by quotation marks
RE_INV_SECT_START = re.compile(r'^\s*\[[^"a-zA-Z]', re.MULTILINE)
RE_INV_SECT_END = re.compile(r'^\s*\[[^\]]*[^"a-zA-Z0-9]\]$', re.MULTILINE)


def check_section_header(content):
    m_begin = RE_INV_SECT_START.search(content)
    m_end = RE_INV_SECT_END.search(content)
    if m_begin or m_end:
        raise RuntimeError(
            'section header must start with \'["\' and end with \'"]\'',
            m_begin, m_end)


def read_toml(content):
    check_section_header(content)
    for k, v in toml.loads(content, collections.OrderedDict).items():
        if len(v.values()) and isinstance(list(v.values())[0], dict):
            raise RuntimeError('malformed section header -- forgot quotes?', k)
        pname, version = split_name(k)
        yield WhitelistRule(pname=pname, version=version, **v)


def read_yaml(content):
    for item in yaml.safe_load(content):
        pname = item.pop('name', None)
        yield WhitelistRule(pname=pname, **item)


def dump_multivalued(val):
    if len(val) == 1:
        return list(val)[0]
    val_l = list(val)
    val_l.sort()
    return val_l


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

    pname = None
    version = None

    def __init__(self, **kw):
        for field in ['pname', 'version']:
            self.__dict__[field] = kw.pop(field, None) or '*'
        for field in ['cve', 'issue_url']:
            v = kw.pop(field, [])
            if isinstance(v, set):
                self.__dict__[field] = v
            elif isinstance(v, list):
                self.__dict__[field] = set(v)
            else:
                self.__dict__[field] = set([v])
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
            if isinstance(kw['until'], (datetime.datetime, datetime.date)):
                self.until = kw.pop('until')
            else:
                self.until = datetime.datetime.strptime(
                    kw.pop('until'), '%Y-%m-%d').date()
        kw.pop('status', '')  # compat
        if kw:
            _log.warning('Unrecognized whitelist keys: {}'.format(kw.keys()))

    @property
    def name(self):
        if self.version == '*':
            return self.pname
        return '{}-{}'.format(self.pname, self.version)

    def dump(self):
        """Returns this entry as a ready-to-serialize dict.

        If this entry has expired, None is returned. The date in the
        'until' field is already formatted.
        """
        if self.until and self.until <= datetime.date.today():
            return None
        res = collections.OrderedDict()
        for field in ['cve', 'comment', 'issue_url']:
            val = getattr(self, field)
            if val:
                res[field] = dump_multivalued(val)
        if self.until:
            res['until'] = str(self.until)
        return res

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
            return False
        if self.version != '*' and self.version != deriv.version:
            return False
        if self.cve and self.cve & deriv.affected_by == set():
            return False
        if self.until and self.until <= datetime.date.today():
            return False
        return True


class Whitelist:
    """Collection of WhitelistRules.

    It can be populated either by reading a config file (`load`) or by
    synthesizing rules from derivations (`add_from`). A whitelist is
    able to save itself into a config file with stable sort order.
    """

    def __init__(self):
        self.entries = collections.OrderedDict()

    def __len__(self):
        return len(self.entries)

    def __getitem__(self, key):
        return self.entries[key]

    def __str__(self):
        return toml.dumps(self.dump()).replace(',]\n', ' ]\n')

    TOML_SECTION_START = re.compile(r'^\[.*\]', re.MULTILINE)
    YAML_SECTION_START = re.compile(r'^-', re.MULTILINE)
    SECTION_FORMAT = re.compile(r'^[a-z0-9_.*-]+$')

    @classmethod
    def load(cls, fobj):
        """Loads whitelist from file-like object.

        The format (TOML or YAML) is guessed using a heuristic.
        """
        content = fobj.read()
        if isinstance(content, bytes):
            content = content.decode('utf-8')
        filename = ''
        if hasattr(fobj, 'name') and fobj.name:
            filename = fobj.name
        elif hasattr(fobj, 'geturl'):
            filename = fobj.geturl()
        try:
            return cls._parse_cfg(content, filename)
        except (toml.TomlDecodeError, IndexError) as e:
            raise RuntimeError('failed to load `{}`: {}'.format(filename, e))

    @classmethod
    def _parse_cfg(cls, content, filename):
        if filename.endswith('.toml'):
            gen = read_toml(content)
        elif filename.endswith('.yaml'):
            gen = read_yaml(content)
        elif cls.TOML_SECTION_START.search(content):
            gen = read_toml(content)
        elif cls.YAML_SECTION_START.search(content):
            gen = read_yaml(content)
        else:
            raise RuntimeError('cannot detect whitelist format')

        self = cls()
        for rule in gen:
            if not self.SECTION_FORMAT.match(rule.pname):
                raise RuntimeError('invalid package selector', rule.pname)
            self.insert(rule)
        return self

    def dump(self):
        """Serializes whitelist into dict."""
        res = collections.OrderedDict()
        for k, v in self.entries.items():
            entry = v.dump()
            if entry is not None:
                res[k] = entry
        return res

    def candidates(self, pname, version):
        """Matching rules in order of decreasing specificity."""
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

    def find(self, derivation):
        """Compiles all matching rules into a `Filtered` object."""
        f = Filtered(derivation)
        for cand in self.candidates(derivation.pname, derivation.version):
            if cand.covers(derivation):
                f.add(cand)
        return f

    def filter(self, derivations):
        """Returns matching rules for all given derivation.

        Rules are wrapped in Filtered objects to keep track.
        """
        return [self.find(deriv) for deriv in derivations]

    def insert(self, rule):
        self.entries[rule.name] = rule

    def update(self, rule):
        name = rule.name
        if name in self.entries:
            self.entries[name].update(rule)
        else:
            self.entries[name] = rule

    def merge(self, other):
        for rule in other.entries.values():
            self.update(rule)

    def add_from(self, deriv):
        self.update(WhitelistRule(
            pname=deriv.pname, version=deriv.version, cve=deriv.affected_by))
