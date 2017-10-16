from pkg_resources import resource_stream
import pytest

from vulnix.whitelist import WhiteList, WhiteListRule


@pytest.yield_fixture
def test_whitelist():
    return resource_stream('vulnix', 'tests/fixtures/test_whitelist.yaml')


def test_scan_rulefile(test_whitelist):
    w = WhiteList()
    w.parse(test_whitelist)
    assert len(w.rules) == 8  # list of CVEs count for each cve_id

    r = w.rules.pop(0)
    assert r.cve == 'CVE-2015-2504'
    assert r.name is None
    assert r.version is None
    assert r.comment is None
    assert r.vendor is None
    assert r.product is None
    assert r.status == 'ignore'
    assert str(r) == r.cve

    r = w.rules.pop(0)
    assert r.cve == 'CVE-2015-7696'
    assert r.name is None
    assert r.version is None
    assert r.comment is None
    assert r.vendor is None
    assert r.product is None
    assert r.status is 'ignore'
    assert str(r) == r.cve

    r = w.rules.pop(0)
    assert r.cve == 'CVE-2015-2503'
    assert r.name is None
    assert r.version is None
    assert r.comment == """microsoft access, accidentally matching the 'access' derivation

https://plan.flyingcircus.io/issues/18544
"""
    assert r.vendor is None
    assert r.product is None
    assert r.status is 'ignore'
    assert str(r) == r.cve

    r = w.rules.pop(0)
    assert r.cve is None
    assert r.name == 'libxslt'
    assert r.version is None
    assert r.comment is None
    assert r.vendor is None
    assert r.product is None
    assert r.status is 'ignore'
    assert str(r) == r.name

    r = w.rules.pop(0)
    assert r.cve == 'CVE-2015-7696'
    assert r.name == 'unzip'
    assert r.version is None
    assert r.comment is None
    assert r.vendor is None
    assert r.product is None
    assert r.status == 'inprogress'
    assert str(r) == '{} ({})'.format(r.name, r.cve)

    r = w.rules.pop(0)
    assert r.cve is None
    assert r.name == 'libxslt'
    assert r.version == '2.0'
    assert r.comment is None
    assert r.vendor is None
    assert r.product is None
    assert r.status is 'ignore'
    assert str(r) == '{}-{}'.format(r.name, r.version)

    r = w.rules.pop(0)
    assert r.cve is None
    assert r.name is None
    assert r.version is None
    assert r.comment is None
    assert r.vendor == 'microsoft'
    assert r.product == 'access'
    assert r.status is 'ignore'
    assert str(r) == '{}-{}'.format(r.vendor, r.product)


def test_concatenate_multiple_whitelists(test_whitelist):
    w = WhiteList()
    w.parse(test_whitelist)
    with resource_stream('vulnix', 'tests/fixtures/test_whitelist2.yaml') as f:
        w.parse(f)

    assert len(w.rules) == 9  # combined list
    assert w.rules[-1].cve == 'CVE-2016-0001'


def test_no_matchable_attribute():
    with pytest.raises(RuntimeError):
        WhiteListRule()


def test_invalid_status():
    with pytest.raises(RuntimeError):
        WhiteListRule(name='libxslt', version='1.2.3', status='foobar')


def test_version_must_be_string():
    with pytest.raises(RuntimeError):
        WhiteListRule(version=1)
