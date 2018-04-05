import datetime
import io
import pytest

from vulnix.whitelist import Whitelist


def check_whitelist_entries(wl):
    assert len(wl) == 4

    assert len(wl['*']) == 1
    entry = wl['*']['*']
    assert entry.cve == set(['CVE-2015-2504', 'CVE-2015-7696'])
    assert entry.issue is None
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
    assert entry.issue == 'https://fb.flyingcircus.io/f/cases/26909/'
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
        Whitelist.load(io.StringIO('[pkg]\nissue = "foobar"'))
