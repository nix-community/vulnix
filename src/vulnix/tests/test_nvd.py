from vulnix.derivation import Derive
from vulnix.nvd import NVD, Archive, decompress
from vulnix.utils import cve_url
from vulnix.whitelist import WhiteList, WhiteListRule
import http.server
import os
import pkg_resources
import pytest
import threading


@pytest.yield_fixture
def http_server():
    os.chdir(os.path.dirname(__file__))
    handler = http.server.SimpleHTTPRequestHandler
    httpd = http.server.HTTPServer(("127.0.0.1", 0), handler)
    port = httpd.socket.getsockname()[1]
    mirror_url = 'http://127.0.0.1:{}/'.format(port)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield mirror_url


def test_update_and_parse(tmpdir, http_server):
    nvd = NVD(mirror=http_server, cache_dir=str(tmpdir))
    nvd.relevant_archives = ['Modified']
    with nvd:
        nvd.update()
        modified = nvd._root['archives']['Modified']
        assert len(modified.products) == 6

        mariadb = modified.products['mariadb']
        mariadb = list(sorted(mariadb, key=lambda x: x.cve_id))
        cve = mariadb[0]
        assert cve.cve_id == 'CVE-2016-6664'
        assert (
            cve_url(cve.cve_id) ==
            'https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-6664')
        cpe = list(sorted(cve.affected_products, key=lambda x: x.vendor))[1]
        assert cpe.versions == {'5.7.14', '5.5.51', '5.6.32'}
        assert cpe.product == 'mysql'
        assert cpe.vendor == 'oracle'


@pytest.fixture
def nvd_modified(tmpdir):
    nvd = NVD(cache_dir=str(tmpdir))
    with nvd:
        a = Archive('Modified')
        nvd._root['archives']['Modified'] = a
        with open(pkg_resources.resource_filename(
                'vulnix', 'tests/nvdcve-2.0-Modified.xml.gz'), 'rb') as f:
            a.parse(decompress(f, str(tmpdir)))
        return nvd


def test_whitelist_selected_versions(nvd_modified):
    w = WhiteList()
    w.rules.append(WhiteListRule(name='mysql', version='5.5.51',
                                 status='inprogress'))

    d1 = Derive(envVars={'name': 'mysql', 'version': '5.5.51'})
    d1.check(nvd_modified, w)
    assert d1.is_affected
    assert d1.status == 'inprogress'

    d2 = Derive(envVars={'name': 'mysql', 'version': '5.7.14'})
    d2.check(nvd_modified, w)
    assert d2.is_affected
    # Bug #24 - status was also set to 'inprogress'
    assert d2.status is None
