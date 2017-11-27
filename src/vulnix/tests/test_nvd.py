from vulnix.nvd import NVD
from vulnix.utils import cve_url
import http.server
import os
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
        assert len(modified.products) == 7

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
