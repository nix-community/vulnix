import hashlib
import http.server
import json
import os
import os.path as p
import threading
from http import HTTPStatus

import pkg_resources
import pytest

from vulnix.nvd import NVD
from vulnix.whitelist import Whitelist


def load(cve):
    return json.loads(
        pkg_resources.resource_string("vulnix", f"tests/fixtures/{cve}.json")
    )


@pytest.fixture
def whitelist_toml():
    return pkg_resources.resource_stream("vulnix", "tests/fixtures/whitelist.toml")


@pytest.fixture
def whitelist_yaml():
    return pkg_resources.resource_stream("vulnix", "tests/fixtures/whitelist.yaml")


@pytest.fixture
def whitelist():
    return Whitelist.load(
        pkg_resources.resource_stream("vulnix", "tests/fixtures/whitelist.toml")
    )


class RequestHandler(http.server.SimpleHTTPRequestHandler):

    def do_GET(self):
        """Serve a GET request from the fixtures directory"""
        fn = p.join(p.dirname(__file__), "fixtures", self.path[1:])
        print("path=", fn)
        try:
            with open(fn, "rb") as f:
                stat = os.fstat(f.fileno())
                content = f.read()
        except (IOError, OSError):
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", self.guess_type(fn))
        self.send_header("Content-Length", stat.st_size)
        self.send_header("ETag", hashlib.sha1(content).hexdigest())
        self.end_headers()
        self.wfile.write(content)


@pytest.fixture(name="http_server")
def fixture_http_server():
    httpd = http.server.HTTPServer(("127.0.0.1", 0), RequestHandler)
    port = httpd.socket.getsockname()[1]
    mirror_url = f"http://127.0.0.1:{port}/"
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield mirror_url


@pytest.fixture
def nvd(tmpdir, http_server):
    _nvd = NVD(mirror=http_server, cache_dir=str(tmpdir))
    _nvd.available_archives = ["modified"]
    with _nvd:
        yield _nvd
