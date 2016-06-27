from vulnix.whitelist import WhiteList
import os.path as p
import pytest


@pytest.yield_fixture
def test_whitelist():
    fn = p.join(p.dirname(__file__), 'test_whitelist.yaml')
    with open(fn) as f:
        yield f


def test_scan_rulefile(test_whitelist):
    w = WhiteList()
    w.parse(test_whitelist)
    assert len(w.rules) == 7  # list of CVEs count for each cve_id

    r = w.rules

    r = w.rules.pop(0)
    assert r.cve == 'CVE-2015-2504'
    assert r.name is None
    assert r.version is None
    assert r.comment is None
    assert r.vendor is None
    assert r.product is None

    r = w.rules.pop(0)
    assert r.cve == 'CVE-2015-7696'
    assert r.name is None
    assert r.version is None
    assert r.comment is None
    assert r.vendor is None
    assert r.product is None

    r = w.rules.pop(0)
    assert r.cve == 'CVE-2015-2503'
    assert r.name is None
    assert r.version is None
    print(r.comment)
    assert r.comment == """microsoft access, accidentally matching the 'access' derivation

https://plan.flyingcircus.io/issues/18544
"""
    assert r.vendor is None
    assert r.product is None

    r = w.rules.pop(0)
    assert r.cve is None
    assert r.name == 'libxslt'
    assert r.version is None
    assert r.comment is None
    assert r.vendor is None
    assert r.product is None

    r = w.rules.pop(0)
    assert r.cve == 'CVE-2015-7696'
    assert r.name == 'unzip'
    assert r.version is None
    assert r.comment is None
    assert r.vendor is None
    assert r.product is None

    r = w.rules.pop(0)
    assert r.cve is None
    assert r.name == 'libxslt'
    assert r.version == '2.0'
    assert r.comment is None
    assert r.vendor is None
    assert r.product is None

    r = w.rules.pop(0)
    assert r.cve is None
    assert r.name is None
    assert r.version is None
    assert r.comment is None
    assert r.vendor == 'microsoft'
    assert r.product == 'access'


def test_concatenate_multiple_whitelists(test_whitelist):
    w = WhiteList()
    w.parse(test_whitelist)
    with open(p.join(p.dirname(__file__), 'test_whitelist2.yaml')) as f:
        w.parse(f)

    assert len(w.rules) == 8  # combined list
    assert w.rules[-1].cve == 'CVE-2016-0001'
