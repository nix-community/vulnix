from http import HTTPStatus
from vulnix.nvd import NVD
from vulnix.whitelist import Whitelist
import hashlib
import http.server
import os
import os.path as p
import pkg_resources
import pytest
import threading


@pytest.fixture
def whitelist_toml():
    return pkg_resources.resource_stream(
        'vulnix', 'tests/fixtures/whitelist.toml')


@pytest.fixture
def whitelist_yaml():
    return pkg_resources.resource_stream(
        'vulnix', 'tests/fixtures/whitelist.yaml')


@pytest.fixture
def whitelist():
    return Whitelist.load(pkg_resources.resource_stream(
        'vulnix', 'tests/fixtures/whitelist.toml'))


class RequestHandler(http.server.SimpleHTTPRequestHandler):

    def do_GET(self):
        """Serve a GET request from the fixtures directory"""
        fn = p.join(p.dirname(__file__), 'fixtures', self.path[1:])
        print("path=", fn)
        try:
            with open(fn, 'rb') as f:
                stat = os.fstat(f.fileno())
                content = f.read()
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND)
        except IOError:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
        self.send_response(HTTPStatus.OK)
        self.send_header('Content-Type', self.guess_type(fn))
        self.send_header('Content-Length', stat.st_size)
        self.send_header('ETag', hashlib.sha1(content).hexdigest())
        self.end_headers()
        self.wfile.write(content)


@pytest.yield_fixture
def http_server():
    httpd = http.server.HTTPServer(("127.0.0.1", 0), RequestHandler)
    port = httpd.socket.getsockname()[1]
    mirror_url = 'http://127.0.0.1:{}/'.format(port)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield mirror_url


@pytest.yield_fixture
def nvd(tmpdir, http_server):
    nvd = NVD(mirror=http_server, cache_dir=str(tmpdir))
    nvd.available_archives = ['modified']
    with nvd:
        yield nvd
