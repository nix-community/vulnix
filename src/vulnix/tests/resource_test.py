import http.server
import os
import signal
from pathlib import Path

import pytest

from vulnix.resource import Resource, open_resources

# fixtures directory
fixtures_path = Path(os.path.dirname(os.path.realpath(__file__))) / "fixtures"


@pytest.fixture(name="http_server")
def fixture_http_server():
    """Spawns a HTTP server in a separate process, serving test fixtures.

    Yields base URL of the HTTP server (e.g., http://localhost:1234/)
    """
    oldcwd = os.getcwd()
    os.chdir(fixtures_path)
    httpd = http.server.HTTPServer(
        ("localhost", 0), http.server.SimpleHTTPRequestHandler
    )
    port = httpd.server_port
    child = os.fork()
    if child == 0:
        signal.alarm(3600)  # safety belt
        httpd.serve_forever()
        return  # never reached
    os.chdir(oldcwd)
    yield f"http://localhost:{port}/"
    os.kill(child, signal.SIGTERM)
    os.wait()


def test_open_local():
    fn = fixtures_path / "whitelist.toml"
    with Resource(fn.as_posix()).open() as f:
        assert f.read() == fn.read_bytes()


def test_open_remote(http_server):
    # pylint: disable=consider-using-with
    with Resource(http_server + "/whitelist.toml").open() as f:
        assert f.read() == (fixtures_path / "whitelist.toml").read_bytes()


def test_multiple_resources(http_server):
    # pylint: disable=consider-using-with
    expected = (fixtures_path / "cpio-2.12.drv").read_bytes()
    gen = open_resources(
        sources=[
            (fixtures_path / "cpio-2.12.drv").as_posix(),
            (fixtures_path / "no-such-file").as_posix(),
            http_server + "cpio-2.12.drv",
            http_server + "file-not-found",
        ]
    )
    assert next(gen).read() == expected  # local file
    assert next(gen).read() == expected  # remote
    with pytest.raises(StopIteration):
        next(gen)  # should skip nonexistent files/urls silently
