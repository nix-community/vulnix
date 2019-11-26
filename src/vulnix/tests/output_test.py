from vulnix.vulnerability import Vulnerability
from vulnix.derivation import Derive
from vulnix.output import Filtered, output, output_text, output_json
from vulnix.whitelist import WhitelistRule
import datetime
import json
import pytest

V = Vulnerability


@pytest.fixture
def deriv():
    d = Derive(name='test-0.2')
    d.store_path = '/nix/store/zsawgflc1fq77ijjzb1369zi6kxnc36j-test-0.2'
    return (d, {
        V('CVE-2018-0001'),
        V('CVE-2018-0002'),
        V('CVE-2018-0003', cvssv3=9.8),
    })


@pytest.fixture
def deriv1():
    return (Derive(name='foo-1'), {V('CVE-2018-0004'), V('CVE-2018-0005')})


@pytest.fixture
def deriv2():
    return (Derive(name='bar-2'), {V('CVE-2018-0006', cvssv3=5.0)})


@pytest.fixture
def filt(deriv):
    return Filtered(*deriv)


@pytest.fixture
def items(deriv, deriv1, deriv2):
    return [Filtered(*deriv), Filtered(*deriv1), Filtered(*deriv2)]


def test_init(deriv):
    f = Filtered(*deriv)
    assert f.report == {
        V('CVE-2018-0001'),
        V('CVE-2018-0002'),
        V('CVE-2018-0003')}
    assert not f.masked


def test_add_unspecific_rule(deriv):
    f = Filtered(*deriv)
    f.add(WhitelistRule(pname='test', version='1.2'))
    assert not f.report


def test_add_rule_with_cves(filt):
    filt.add(WhitelistRule(pname='test', version='1.2', cve={'CVE-2018-0001'}))
    assert filt.report == {V('CVE-2018-0002'), V('CVE-2018-0003')}
    assert filt.masked == {V('CVE-2018-0001')}


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
    output_text(wl_items, show_whitelisted=True)
    assert capsys.readouterr().out == """\
2 derivations with active advisories

------------------------------------------------------------------------
foo-1

CVE                                                CVSSv3
https://nvd.nist.gov/vuln/detail/CVE-2018-0005
https://nvd.nist.gov/vuln/detail/CVE-2018-0004  [whitelisted]

Issue(s):
https://tracker/4

------------------------------------------------------------------------
test-0.2

/nix/store/zsawgflc1fq77ijjzb1369zi6kxnc36j-test-0.2
CVE                                                CVSSv3
https://nvd.nist.gov/vuln/detail/CVE-2018-0003     9.8
https://nvd.nist.gov/vuln/detail/CVE-2018-0001
https://nvd.nist.gov/vuln/detail/CVE-2018-0002

------------------------------------------------------------------------
bar-2

CVE                                                CVSSv3
https://nvd.nist.gov/vuln/detail/CVE-2018-0006     5.0  [whitelisted]

Comment:
* irrelevant
"""


def test_output_json(wl_items, capsys):
    output_json(wl_items)
    assert json.loads(capsys.readouterr().out) == [
        {'affected_by': ['CVE-2018-0005'],
         'derivation': None,
         'name': 'foo-1',
         'pname': 'foo',
         'version': '1',
         'whitelisted': ['CVE-2018-0004'],
         'cvssv3_basescore': {}},
        {'affected_by': ['CVE-2018-0001', 'CVE-2018-0002', 'CVE-2018-0003'],
         'derivation': '/nix/store/zsawgflc1fq77ijjzb1369zi6kxnc36j-test-0.2',
         'name': 'test-0.2',
         'pname': 'test',
         'version': '0.2',
         'whitelisted': [],
         'cvssv3_basescore': {
             'CVE-2018-0003': 9.8,
         }},
    ]


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
