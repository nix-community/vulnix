from vulnix.nvd import NVD, Vulnerability, Node
import http.server
import json
import os
import pkg_resources
import pytest
import threading


@pytest.yield_fixture
def http_server():
    os.chdir(os.path.dirname(__file__) + '/fixtures')
    handler = http.server.SimpleHTTPRequestHandler
    httpd = http.server.HTTPServer(("127.0.0.1", 0), handler)
    port = httpd.socket.getsockname()[1]
    mirror_url = 'http://127.0.0.1:{}/'.format(port)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield mirror_url


@pytest.fixture
def nvd(tmpdir, http_server):
    nvd = NVD(mirror=http_server, cache_dir=str(tmpdir))
    nvd.relevant_archives = ['modified']
    return nvd


def test_update(nvd):
    with nvd:
        nvd.update()
        # XXX assertions missing


def load(cve):
    return json.loads(pkg_resources.resource_string(
        'vulnix', 'tests/fixtures/{}.json'.format(cve)))


def test_parse_vuln():
    v = Vulnerability.parse(load('CVE-2019-10160'))
    assert v.cve_id == 'CVE-2019-10160'
    assert v.nodes == [
        Node('python', 'python',
             ['=3.5', '=3.6', '=3.7', '>=3.8.0a4', '<=3.8.0b1'])
    ]


def test_compress_identical_vendor_product():
    v = Vulnerability.parse(load('CVE-2016-2183'))
    # redhat entries do not get compressed, python & openssl do
    assert v.nodes == [
        Node('redhat', 'jboss_enterprise_application_platform', ['=6.0.0']),
        Node('redhat', 'jboss_enterprise_web_server', ['=1.0.0']),
        Node('redhat', 'jboss_enterprise_web_server', ['=2.0.0']),
        Node('redhat', 'jboss_web_server', ['=3.0']),
        Node('python', 'python', ['=3.3', '=3.4.0', '=3.5', '=3.6']),
        Node('openssl', 'openssl', [
            '=1.0.1a', '=1.0.1b', '=1.0.1c', '=1.0.1d', '=1.0.1e', '=1.0.1f',
            '=1.0.1g', '=1.0.1h', '=1.0.1i', '=1.0.1j', '=1.0.1k', '=1.0.1l',
            '=1.0.1m', '=1.0.1n', '=1.0.1o', '=1.0.1p', '=1.0.1q', '=1.0.1r',
            '=1.0.1t', '=1.0.2a', '=1.0.2b', '=1.0.2c', '=1.0.2d', '=1.0.2e',
            '=1.0.2f', '=1.0.2h'
        ])
    ]


def test_ignore_AND_operator():
    # The AND operators are usually incomplete or incorrect. We prefer to get a
    # few more false positives by ignoring them altogether.
    v = Vulnerability.parse(load('CVE-2010-0748'))
    assert v.nodes == [
        Node('transmissionbt', 'transmission', ['<1.92'])
    ]
