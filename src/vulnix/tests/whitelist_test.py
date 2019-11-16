from vulnix.derivation import Derive
from vulnix.output import Filtered
from vulnix.vulnerability import Vulnerability
from vulnix.whitelist import Whitelist, WhitelistRule
import datetime
import freezegun
import io
import pytest

V = Vulnerability


@freezegun.freeze_time('2018-02-28')
def check_whitelist_entries(wl):
    assert len(wl) == 6

    entry = wl['*']
    assert entry.cve == {'CVE-2015-2504', 'CVE-2015-7696'}
    assert entry.issue_url == set()
    assert entry.comment == []
    assert not hasattr(entry, 'status')

    assert wl['libxslt'].comment == ["broken, won't fix"]
    assert wl['libxslt-2.0'].until == datetime.date(2018, 3, 1)
    assert wl['unzip'].cve == {'CVE-2015-7696'}
    assert wl['audiofile-0.3.2'] is not None

    entry = wl['audiofile-0.3.6']
    assert entry.issue_url == {'https://fb.flyingcircus.io/f/cases/26909/'}
    assert entry.cve == {'CVE-2017-6827', 'CVE-2017-6834', 'CVE-2017-6828'}


def test_from_yaml(whitelist_yaml):
    check_whitelist_entries(Whitelist.load(whitelist_yaml))


def test_from_toml(whitelist_toml):
    check_whitelist_entries(Whitelist.load(whitelist_toml))


def test_neither_name_nor_cve():
    with pytest.raises(RuntimeError):
        Whitelist.load(io.StringIO('-\n  comment: invalid entry\n'))


def test_parse_until():
    wl = Whitelist.load(io.StringIO('["libarchive"]\nuntil = "2019-03-10"\n'))
    assert len(wl.entries) == 1
    assert wl.entries['libarchive'].until == datetime.date(2019, 3, 10)


def test_match_pname_version():
    rule = WhitelistRule(pname='libxslt', version='2.0')
    assert rule.covers(Derive(name='libxslt-2.0'))
    assert not rule.covers(Derive(name='libxslt-2.1'))


def test_match_pname_only():
    rule = WhitelistRule(pname='libxslt', version='*')
    assert rule.covers(Derive(name='libxslt-2.0'))
    assert rule.covers(Derive(name='libxslt-2.1'))
    assert not rule.covers(Derive(name='libxml2-2.0'))


def test_match_pname_version_cve():
    rule = WhitelistRule(pname='cpio', version='2.12', cve=['CVE-2015-1197'])
    assert rule.covers(Derive(name='cpio-2.12'), {V('CVE-2015-1197')})
    assert not rule.covers(Derive(name='cpio-2.12'), {V('CVE-2015-1198')})


def test_match_cve_only():
    rule = WhitelistRule(cve=['CVE-2015-1197', 'CVE-2016-2037'])
    assert rule.covers(Derive(name='cpio-2.12'), {V('CVE-2015-1197')})
    assert not rule.covers(Derive(name='cpio-2.12'), {V('CVE-2016-2038')})


def test_match_partial():
    rule = WhitelistRule(cve=['CVE-2015-1197', 'CVE-2016-2037'])
    assert rule.covers(
            Derive(name='cpio-2.12'), {V('CVE-2015-1197'), V('CVE-2015-1198')})


def test_until(whitelist_toml):
    rule = WhitelistRule(pname='libxslt', until='2018-04-12')
    d = Derive(name='libxslt-2.0')
    with freezegun.freeze_time('2018-04-11'):
        assert rule.covers(d)
    with freezegun.freeze_time('2018-04-12'):
        assert not rule.covers(d)


def test_not_whitelisted(whitelist):
    filtered = whitelist.find(Derive(name='cpio-2.12'), {V('CVE-2016-2037')})
    assert filtered.rules == []
    assert filtered.report == {V('CVE-2016-2037')}


def test_filter(whitelist):
    affected = {
        # not filtered
        Derive(name='cpio-2.12'): {V('CVE-2016-2037')},
        # partially filtered
        Derive(name='audiofile-0.3.6'): {
            V('CVE-2017-6826'), V('CVE-2017-6827')},
        # fully filtered
        Derive(name='unzip-6.0'): {V('CVE-2015-7696')},
        # fully filtered w/o specific CVEs
        Derive(name='audiofile-0.3.2'): {V('CVE-2018-2668')},
    }
    f = whitelist.filter(affected)
    assert f[0].report == {V('CVE-2016-2037')}
    assert f[1].report == {V('CVE-2017-6826')}
    assert f[2].report == set()
    assert f[3].report == set()


def test_merge(whitelist):
    new = Whitelist.load(io.StringIO("""\
["libxslt-2.0"]
until = "2018-02-25"
comment = "latest date wins"

["audiofile-0.3.6"]
cve = ["CVE-2017-6827", "CVE-2017-6839"]
comment = "new stuff should be appended"
issue_url = "https://github.com/NixOS/nixpkgs/issues/30959"

["libtasn1-4.12"]
cve = ["CVE-2017-10790"]
"""))
    whitelist.merge(new)
    assert len(whitelist) == 7

    libxslt = whitelist['libxslt-2.0']
    assert libxslt.until == datetime.date(2018, 3, 1)
    assert libxslt.comment == ['latest date wins']

    audiofile = whitelist['audiofile-0.3.6']
    assert audiofile.cve == {
        'CVE-2017-6827',
        'CVE-2017-6834',
        'CVE-2017-6828',
        'CVE-2017-6839',
    }
    assert audiofile.comment == [
        'some issues not fixed upstream',
        'new stuff should be appended',
    ]
    assert audiofile.issue_url == {
        'https://fb.flyingcircus.io/f/cases/26909/',
        'https://github.com/NixOS/nixpkgs/issues/30959',
    }

    libtasn1 = whitelist['libtasn1-4.12']
    assert libtasn1.cve == {'CVE-2017-10790'}


def test_merge_into_empty():
    wl = Whitelist()
    new = Whitelist.load(io.StringIO("""\
["libxslt"]
["audiofile-0.3.6"]
"""))
    wl.merge(new)
    assert set(wl.entries.keys()) == {'libxslt', 'audiofile-0.3.6'}


def test_until_latest_wins(whitelist):
    new = Whitelist.load(io.StringIO("""\
["libxslt-2.0"]
until = "2018-03-02"

["audiofile-0.3.2"]
until = "2018-04-01"
"""))
    whitelist.merge(new)
    assert whitelist['libxslt-2.0'].until == datetime.date(2018, 3, 2)
    assert whitelist['audiofile-0.3.2'].until == datetime.date(2018, 4, 1)


@freezegun.freeze_time('2018-02-28')
def test_dump_str(whitelist):
    assert str(whitelist) == """\
["*"]
cve = [ "CVE-2015-2504", "CVE-2015-7696" ]

[libxslt]
comment = "broken, won't fix"

[unzip]
cve = "CVE-2015-7696"

["libxslt-2.0"]
cve = [ "CVE-2015-9019", "CVE-2017-2477" ]
until = "2018-03-01"

["audiofile-0.3.2"]

["audiofile-0.3.6"]
cve = [ "CVE-2017-6827", "CVE-2017-6828", "CVE-2017-6834" ]
comment = "some issues not fixed upstream"
issue_url = "https://fb.flyingcircus.io/f/cases/26909/"
"""


@freezegun.freeze_time('2018-03-01')
def test_dump_str_remove_outdated(whitelist):
    assert str(whitelist) == """\
["*"]
cve = [ "CVE-2015-2504", "CVE-2015-7696" ]

[libxslt]
comment = "broken, won't fix"

[unzip]
cve = "CVE-2015-7696"

["audiofile-0.3.2"]

["audiofile-0.3.6"]
cve = [ "CVE-2017-6827", "CVE-2017-6828", "CVE-2017-6834" ]
comment = "some issues not fixed upstream"
issue_url = "https://fb.flyingcircus.io/f/cases/26909/"
"""


@freezegun.freeze_time('2018-02-28')
def test_dump_add_cve(whitelist):
    whitelist.add_from(Filtered(Derive(name='libxslt-2.0'), {
        V('CVE-2019-13118'),
    }))
    assert """\
["libxslt-2.0"]
cve = [ "CVE-2015-9019", "CVE-2017-2477", "CVE-2019-13118" ]
until = "2018-03-01"
""" in str(whitelist)


def test_toml_missing_quote():
    t = io.StringIO("""\
[libxslt-2.0.1]
comment = "unquoted, triggers TOML's table syntax inadvertently"
""")
    with pytest.raises(RuntimeError):
        Whitelist.load(t)


def test_toml_malformed_url():
    with pytest.raises(ValueError):
        Whitelist.load(io.StringIO('["pkg"]\nissue_url = "foobar"'))


def test_section_header_unexpected_space():
    with pytest.raises(RuntimeError):
        Whitelist.load(io.StringIO("""
["ok-section-1.0"]

[ "broken-section-1.1" ]
comment = "whitespace confuses TOML parser"
"""))


def test_section_header_unexpected_space_2():
    with pytest.raises(RuntimeError):
        Whitelist.load(io.StringIO("""
["broken-section 1.2"]
comment = "incorrect whitespace between package and version"
"""))


def test_section_header_alphanumeric():
    Whitelist.load(io.StringIO("""
[systemd-236]
comment = "section headers consisting only of alphanum chars are ok"
"""))
