import gzip
import io
import zipfile

import pytest
import requests
from conftest import fixtures_path, load

import vulnix.nvd
from vulnix.nvd import NVD, Archive
from vulnix.vulnerability import Node, Vulnerability


def test_update(nvd):
    # pylint: disable=protected-access
    nvd.update()
    assert len(nvd._root["advisory"]) == 3
    cve = nvd.by_id("CVE-2010-0748")
    assert cve == Vulnerability.parse(load("CVE-2010-0748"))
    assert cve == nvd.by_product("transmission")[0]


def test_parse_vuln():
    v = Vulnerability.parse(load("CVE-2019-10160"))
    assert v.cve_id == "CVE-2019-10160"
    assert v.nodes == [
        Node("python", "python", [">=2.7.0", "<2.7.17"]),
        Node("python", "python", [">=3.5.0", "<3.5.8"]),
        Node("python", "python", [">=3.6.0", "<3.6.9"]),
        Node("python", "python", [">=3.7.0", "<3.7.4"]),
        Node("python", "python", "3.8.0-alpha4"),
        Node("python", "python", "3.8.0-beta1"),
        Node("redhat", "virtualization", "4.0"),
    ]


def _response(status, content=b"", headers=None):
    r = requests.Response()
    r.status_code = status
    r._content = content  # pylint: disable=protected-access
    r.headers.update(headers or {})
    r.reason = "Not Found" if status == 404 else "OK"
    return r


@pytest.fixture(name="zip_only_mirror")
def fixture_zip_only_mirror(monkeypatch):
    """A mirror that gives 404 for the .json.gz feeds and serves the same
    data as .json.zip. Records each request."""
    data = gzip.decompress((fixtures_path / "nvdcve-2.0-modified.json.gz").read_bytes())
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("nvdcve-2.0-modified.json", data)
    requests_seen = []

    def get(url, headers=None, timeout=None):  # pylint: disable=unused-argument
        requests_seen.append((url, dict(headers or {})))
        if url.endswith(".json.zip"):
            if (headers or {}).get("If-None-Match") == "zip-etag":
                return _response(304)
            return _response(200, buf.getvalue(), {"ETag": "zip-etag"})
        return _response(404)

    monkeypatch.setattr(vulnix.nvd.requests, "get", get)
    return requests_seen


def test_update_falls_back_to_zip(tmpdir, zip_only_mirror):
    # pylint: disable=protected-access
    nvd = NVD(mirror="http://mirror/", cache_dir=str(tmpdir))
    nvd.available_archives = ["modified"]
    with nvd:
        nvd.update()
        assert len(nvd._root["advisory"]) == 3
        cve = nvd.by_id("CVE-2010-0748")
        assert cve == Vulnerability.parse(load("CVE-2010-0748"))
        assert cve == nvd.by_product("transmission")[0]
        assert [u for u, _ in zip_only_mirror] == [
            "http://mirror/nvdcve-2.0-modified.json.gz",
            "http://mirror/nvdcve-2.0-modified.json.zip",
        ]
        # The ETag of the .zip URL is kept: the next download is a 304.
        arch = Archive("modified")
        assert not arch.download(nvd.mirror, nvd.meta)
        assert zip_only_mirror[-1] == (
            "http://mirror/nvdcve-2.0-modified.json.zip",
            {"If-None-Match": "zip-etag"},
        )


def test_download_raises_when_zip_is_missing_too(tmpdir, monkeypatch):
    monkeypatch.setattr(vulnix.nvd.requests, "get", lambda *a, **kw: _response(404))
    nvd = NVD(mirror="http://mirror/", cache_dir=str(tmpdir))
    with nvd:
        with pytest.raises(requests.HTTPError):
            Archive("modified").download(nvd.mirror, nvd.meta)
