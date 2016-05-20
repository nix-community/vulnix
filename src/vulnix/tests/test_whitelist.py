from vulnix.whitelist import WhiteList
import os.path


def test_scan_rulefile():
    test_file = os.path.join(os.path.dirname(__file__), 'whitelist.yaml')
    w = WhiteList()
    w.parse(test_file)
    assert len(w.rules) == 5

    r = w.rules.pop(0)
    assert r.cve == 'CVE-2015-2503'
    assert r.name is None
    assert r.version is None
    assert r.comment == """\
microsoft access, accidentally matching the 'access' derivation
https://plan.flyingcircus.io/issues/18544\
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
