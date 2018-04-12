import datetime
import freezegun
import io
import pytest

from vulnix.whitelist import Whitelist, WhitelistItem, MATCH_TEMP, MATCH_PERM
from vulnix.derivation import Derive


def check_whitelist_entries(wl):
    assert len(wl) == 4

    assert len(wl['*']) == 1
    entry = wl['*']['*']
    assert entry.cve == set(['CVE-2015-2504', 'CVE-2015-7696'])
    assert entry.issue_url is None
    assert entry.comment is None
    assert not hasattr(entry, 'status')

    assert len(wl['libxslt']) == 2
    assert wl['libxslt']['*'].comment == "broken, won't fix"
    assert wl['libxslt']['2.0'].until == datetime.date(2018, 3, 1)

    assert len(wl['unzip']) == 1
    assert wl['unzip']['*'].cve == set(['CVE-2015-7696'])

    assert len(wl['audiofile']) == 2
    assert wl['audiofile']['0.3.2'] is not None
    entry = wl['audiofile']['0.3.6']
    assert entry.issue_url == 'https://fb.flyingcircus.io/f/cases/26909/'
    assert entry.cve == set(['CVE-2017-6827', 'CVE-2017-6834', 'CVE-2017-6828'])


def test_from_yaml(whitelist_yaml):
    check_whitelist_entries(Whitelist.load(whitelist_yaml))


def test_from_toml(whitelist_toml):
    check_whitelist_entries(Whitelist.load(whitelist_toml))


def test_neither_name_nor_cve():
    with pytest.raises(RuntimeError):
        Whitelist.load(io.StringIO('-\n  comment: invalid entry\n'))


def test_toml_missing_quote():
    t = io.StringIO("""\
[libxslt-2.0.1]
comment = "unquoted, triggers TOML's table syntax inadvertently"
""")
    with pytest.raises(RuntimeError):
        Whitelist.load(t)


def test_toml_malformed_url():
    with pytest.raises(ValueError):
        Whitelist.load(io.StringIO('[pkg]\nissue_url = "foobar"'))


def test_match_pname_version():
    wli = WhitelistItem(pname='libxslt', version='2.0')
    assert wli.covers(Derive(name='libxslt-2.0')) == (MATCH_PERM, wli)
    assert not wli.covers(Derive(name='libxslt-2.1'))


def test_match_pname_only():
    wli = WhitelistItem(pname='libxslt', version='*')
    assert wli.covers(Derive(name='libxslt-2.0')) == (MATCH_PERM, wli)
    assert wli.covers(Derive(name='libxslt-2.1')) == (MATCH_PERM, wli)
    assert not wli.covers(Derive(name='libxml2-2.0'))


def test_match_pname_version_cve():
    wli = WhitelistItem(pname='cpio', version='2.12', cve=['CVE-2015-1197'])
    d = Derive(name='cpio-2.12', affected_by={'CVE-2015-1197'})
    assert wli.covers(d) == (MATCH_PERM, wli)
    d.affected_by.add('CVE-2016-2037')
    assert not wli.covers(d)


def test_match_cve_only():
    wli = WhitelistItem(cve=['CVE-2015-1197', 'CVE-2016-2037'])
    d = Derive(name='cpio-2.12', affected_by={'CVE-2015-1197'})
    assert wli.covers(d) == (MATCH_PERM, wli)
    d.affected_by.add('CVE-2016-2038')
    assert not wli.covers(d)


def test_until(whitelist_toml):
    wli = WhitelistItem(pname='libxslt', until='2018-04-12')
    d = Derive(name='libxslt-2.0')
    with freezegun.freeze_time('2018-04-11'):
        assert wli.covers(d) == (MATCH_TEMP, wli)
    with freezegun.freeze_time('2018-04-12'):
        assert not wli.covers(d)


def test_not_whitelisted(whitelist):
    d = Derive(name='cpio-2.12', affected_by={'CVE-2016-2037'})
    assert whitelist.filter([d]) == ([d], [])


def test_filter(whitelist):
    # not affected
    d1 = Derive(name='cpio-2.12', affected_by={'CVE-2016-2037'})
    # affected, w/comment
    d2 = Derive(name='libxslt-2.0', affected_by={'CVE-2017-5029'})
    # affected, w/url
    d3 = Derive(name='audiofile-0.3.6', affected_by={'CVE-2017-6827'})
    # not affected
    d4 = Derive(name='unzip-6.0', affected_by={'CVE-2016-9844'})
    derivations = [d1, d2, d3, d4]
    unfiltered, filtered = whitelist.filter(derivations)
    assert unfiltered == [d1, d4]
    assert [e.deriv.pname for e in filtered] == ['libxslt', 'audiofile']
    assert filtered[0].wli.comment is not None
    assert filtered[1].wli.issue_url is not None
