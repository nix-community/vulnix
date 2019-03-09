from vulnix.derivation import Derive
from vulnix.output import Filtered, output, output_text, output_json
from vulnix.whitelist import WhitelistRule
import datetime
import json
import pytest


@pytest.fixture
def deriv():
    d = Derive(
        name='test-0.2',
        affected_by={'CVE-2018-0001', 'CVE-2018-0002', 'CVE-2018-0003'})
    d.store_path = '/nix/store/zsawgflc1fq77ijjzb1369zi6kxnc36j-test-0.2'
    return d


@pytest.fixture
def deriv1():
    return Derive(name='foo-1', affected_by={'CVE-2018-0004', 'CVE-2018-0005'})


@pytest.fixture
def deriv2():
    return Derive(name='bar-2', affected_by={'CVE-2018-0006'})


@pytest.fixture
def filt(deriv):
    return Filtered(deriv)


@pytest.fixture
def items(deriv, deriv1, deriv2):
    return [Filtered(deriv), Filtered(deriv1), Filtered(deriv2)]


def test_init(deriv):
    f = Filtered(deriv)
    assert f.report == deriv.affected_by
    assert not f.masked


def test_add_unspecific_rule(deriv):
    f = Filtered(deriv)
    f.add(WhitelistRule(pname='test', version='1.2'))
    assert not f.report


def test_add_rule_with_cves(filt):
    filt.add(WhitelistRule(pname='test', version='1.2', cve={'CVE-2018-0001'}))
    assert filt.report == {'CVE-2018-0002', 'CVE-2018-0003'}
    assert filt.masked == {'CVE-2018-0001'}


def test_add_temporary_whitelist(filt):
    assert not filt.until
    filt.add(WhitelistRule(pname='test', version='1.2', until='2018-03-05'))
    assert filt.until == datetime.date(2018, 3, 5)


@pytest.fixture
def wl_items(items):
    # makes deriv1 list only one CVE
    items[1].add(WhitelistRule(
        cve={'CVE-2018-0004'}, issue_url='https://tracker/4'))
    # makes deriv2 disappear completely
    items[2].add(WhitelistRule(pname='bar', comment='irrelevant'))
    return items


def test_output_text(wl_items, capsys):
    output_text(wl_items)
    assert capsys.readouterr().out == """\
2 derivations with active advisories
1 derivations left out due to whitelisting

------------------------------------------------------------------------
foo-1

CVEs:
\tCVE-2018-0005

------------------------------------------------------------------------
test-0.2

CVEs:
\tCVE-2018-0001
\tCVE-2018-0002
\tCVE-2018-0003

use --show-whitelisted to see derivations with only whitelisted CVEs
"""


def test_output_text_verbose(wl_items, capsys):
    output_text(wl_items, show_whitelisted=True, verbose=True)
    assert capsys.readouterr().out == """\
2 derivations with active advisories

------------------------------------------------------------------------
foo-1

CVEs:
\thttps://nvd.nist.gov/vuln/detail/CVE-2018-0005
\thttps://nvd.nist.gov/vuln/detail/CVE-2018-0004 (whitelisted)
Issue(s):
\thttps://tracker/4

------------------------------------------------------------------------
test-0.2

/nix/store/zsawgflc1fq77ijjzb1369zi6kxnc36j-test-0.2
CVEs:
\thttps://nvd.nist.gov/vuln/detail/CVE-2018-0001
\thttps://nvd.nist.gov/vuln/detail/CVE-2018-0002
\thttps://nvd.nist.gov/vuln/detail/CVE-2018-0003

------------------------------------------------------------------------
bar-2

CVEs:
\thttps://nvd.nist.gov/vuln/detail/CVE-2018-0006 (whitelisted)
Comment:
\tirrelevant
"""


def test_output_json(wl_items, capsys):
    output_json(wl_items)
    assert json.loads(capsys.readouterr().out) == [
        {'affected_by': ['CVE-2018-0005'],
         'derivation': None,
         'name': 'foo-1',
         'pname': 'foo',
         'version': '1',
         'whitelisted': ['CVE-2018-0004']},
        {'affected_by': ['CVE-2018-0001', 'CVE-2018-0002', 'CVE-2018-0003'],
         'derivation': '/nix/store/zsawgflc1fq77ijjzb1369zi6kxnc36j-test-0.2',
         'name': 'test-0.2',
         'pname': 'test',
         'version': '0.2',
         'whitelisted': []}]


def test_exitcode(items, capsys):
    assert output([], json=True) == 0
    # something to report
    assert output(items) == 2
    # everything masked
    for i in items:
        i.add(WhitelistRule(pname=i.derivation.pname))
    assert output(items) == 0
    assert output(items, show_whitelisted=True) == 1
    capsys.readouterr()  # swallow stdout/stderr: it doesn't matter here
