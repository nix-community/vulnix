from vulnix.resource import Resource, open_resources
import http.server
import os
import pkg_resources
import pytest
import signal

# local file prefix to the fixtures directory
local = pkg_resources.resource_filename('vulnix', 'tests/fixtures/')


@pytest.yield_fixture
def http_server():
    """Spawns a HTTP server in a separate process, serving test fixtures.

    Yields base URL of the HTTP server (e.g., http://localhost:1234/)
    """
    oldcwd = os.getcwd()
    os.chdir(pkg_resources.resource_filename('vulnix', 'tests/fixtures'))
    httpd = http.server.HTTPServer(
        ('localhost', 0), http.server.SimpleHTTPRequestHandler)
    port = httpd.server_port
    child = os.fork()
    if child == 0:
        signal.alarm(3600)  # safety belt
        httpd.serve_forever()
        return  # never reached
    os.chdir(oldcwd)
    yield 'http://localhost:{}/'.format(port)
    os.kill(child, signal.SIGTERM)
    os.wait()


def test_open_local():
    fn = local + 'whitelist.toml'
    with Resource(fn).open() as f:
        assert f.read() == open(fn, 'rb').read()


def test_open_remote(http_server):
    with Resource(http_server + 'whitelist.toml').open() as f:
        assert f.read() == open(local + 'whitelist.toml', 'rb').read()


def test_multiple_resources(http_server):
    expected = open(local + 'cpio-2.12.drv', 'rb').read()
    gen = open_resources(sources=[
        local + 'cpio-2.12.drv',
        local + 'no-such-file',
        http_server + 'cpio-2.12.drv',
        http_server + 'file-not-found',
    ])
    assert next(gen).read() == expected  # local file
    assert next(gen).read() == expected  # remote
    with pytest.raises(StopIteration):
        next(gen)  # should skip nonexistent files/urls silently
