import copy
import gzip
import hashlib
import io
import json
import zipfile

import pytest
import requests
import transaction
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


FEED = json.loads(
    gzip.decompress((fixtures_path / "nvdcve-2.0-modified.json.gz").read_bytes())
)
GZ_URL = "http://mirror/nvdcve-2.0-modified.json.gz"
ZIP_URL = "http://mirror/nvdcve-2.0-modified.json.zip"


def _feed(timestamp, without_configurations=()):
    """Returns the fixture feed as JSON bytes, with a new timestamp.
    A timestamp of None removes the field.

    The CVEs in `without_configurations` lose their configurations, thus
    their nodes, to tell this version of the record from the fixture."""
    feed = copy.deepcopy(FEED)
    if timestamp is None:
        del feed["timestamp"]
    else:
        feed["timestamp"] = timestamp
    for item in feed["vulnerabilities"]:
        if item["cve"]["id"] in without_configurations:
            del item["cve"]["configurations"]
    return json.dumps(feed).encode()


def _zip(data):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("nvdcve-2.0-modified.json", data)
    return buf.getvalue()


def _response(status, content=b"", headers=None):
    r = requests.Response()
    r.status_code = status
    r._content = content  # pylint: disable=protected-access
    r.headers.update(headers or {})
    r.reason = {200: "OK", 304: "Not Modified", 404: "Not Found"}[status]
    return r


class FakeMirror:  # pylint: disable=too-few-public-methods
    """Serves `files` by URL, with a content hash as ETag. Records each
    request."""

    def __init__(self):
        self.files = {}
        self.requests = []

    def get(self, url, headers=None, timeout=None):  # pylint: disable=unused-argument
        headers = dict(headers or {})
        self.requests.append((url, headers))
        if url not in self.files:
            return _response(404)
        content = self.files[url]
        etag = hashlib.sha1(content).hexdigest()
        if headers.get("If-None-Match") == etag:
            return _response(304)
        return _response(200, content, {"ETag": etag})


@pytest.fixture(name="mirror")
def fixture_mirror(monkeypatch):
    m = FakeMirror()
    monkeypatch.setattr(vulnix.nvd.requests, "get", m.get)
    return m


@pytest.fixture(name="fake_nvd")
def fixture_fake_nvd(tmpdir, mirror):  # pylint: disable=unused-argument
    _nvd = NVD(mirror="http://mirror/", cache_dir=str(tmpdir))
    _nvd.available_archives = ["modified"]
    with _nvd:
        yield _nvd


def _load(nvd):
    """Downloads the modified feed and adds it, as NVD.update() does."""
    arch = Archive("modified")
    changed = arch.download(nvd.mirror, nvd.meta)
    nvd.add(arch)
    return changed


def test_update_falls_back_to_zip(fake_nvd, mirror):
    # pylint: disable=protected-access
    mirror.files[ZIP_URL] = _zip(_feed(FEED["timestamp"]))
    fake_nvd.update()
    assert len(fake_nvd._root["advisory"]) == 3
    cve = fake_nvd.by_id("CVE-2010-0748")
    assert cve == Vulnerability.parse(load("CVE-2010-0748"))
    assert cve == fake_nvd.by_product("transmission")[0]
    assert [url for url, _ in mirror.requests] == [GZ_URL, ZIP_URL]
    # The ETag of the .zip URL is kept: the next download is a 304.
    assert not _load(fake_nvd)
    assert mirror.requests[-1][0] == ZIP_URL
    assert "If-None-Match" in mirror.requests[-1][1]


def test_download_raises_when_zip_is_missing_too(fake_nvd):
    with pytest.raises(requests.HTTPError):
        _load(fake_nvd)


def test_older_zip_feed_is_skipped(fake_nvd, mirror):
    mirror.files[GZ_URL] = gzip.compress(_feed("2026-09-24T16:00:04.1977477"))
    assert _load(fake_nvd)
    newer_nodes = fake_nvd.by_id("CVE-2010-0748").nodes
    assert newer_nodes

    # The .gz feed gives 404, and the .zip feed is older.
    del mirror.files[GZ_URL]
    mirror.files[ZIP_URL] = _zip(
        _feed("2026-09-24T14:00:03.1234567", without_configurations={"CVE-2010-0748"})
    )
    assert not _load(fake_nvd)
    assert fake_nvd.by_id("CVE-2010-0748").nodes == newer_nodes
    # The older feed does not save its ETag, so it is examined again next time.
    assert not fake_nvd.meta.headers_for(ZIP_URL)
    assert fake_nvd.meta.feed_timestamp["modified"] == "2026-09-24T16:00:04.1977477"


def test_newer_zip_feed_is_loaded(fake_nvd, mirror):
    mirror.files[GZ_URL] = gzip.compress(_feed("2026-09-24T14:00:03.1234567"))
    assert _load(fake_nvd)

    del mirror.files[GZ_URL]
    mirror.files[ZIP_URL] = _zip(
        _feed("2026-09-24T16:00:04.1977477", without_configurations={"CVE-2010-0748"})
    )
    assert _load(fake_nvd)
    assert fake_nvd.by_id("CVE-2010-0748").nodes == []
    assert fake_nvd.meta.headers_for(ZIP_URL)
    assert fake_nvd.meta.feed_timestamp["modified"] == "2026-09-24T16:00:04.1977477"


def test_feed_without_timestamp_is_loaded(fake_nvd, mirror):
    mirror.files[GZ_URL] = gzip.compress(_feed("2026-09-24T16:00:04.1977477"))
    assert _load(fake_nvd)

    # The age of this feed is not known, so it is loaded. The saved
    # timestamp stays.
    del mirror.files[GZ_URL]
    mirror.files[ZIP_URL] = _zip(_feed(None, without_configurations={"CVE-2010-0748"}))
    assert _load(fake_nvd)
    assert fake_nvd.by_id("CVE-2010-0748").nodes == []
    assert fake_nvd.meta.feed_timestamp["modified"] == "2026-09-24T16:00:04.1977477"


def test_cache_without_feed_timestamps(tmpdir, mirror):
    # A cache from an older vulnix: ETags, but no feed timestamps.
    old = NVD(mirror="http://mirror/", cache_dir=str(tmpdir))
    with old:
        old.meta.update_headers_for(GZ_URL, {"ETag": "old-etag"})
        transaction.commit()

    mirror.files[ZIP_URL] = _zip(_feed("2026-09-24T14:00:03.1234567"))
    nvd = NVD(mirror="http://mirror/", cache_dir=str(tmpdir))
    with nvd:
        assert nvd.meta.feed_timestamp is None
        assert _load(nvd)
        assert nvd.by_id("CVE-2010-0748")
        transaction.commit()

    # The timestamp is saved in the cache, and an older feed is skipped.
    mirror.files[ZIP_URL] = _zip(_feed("2026-09-24T12:00:02.1234567"))
    nvd = NVD(mirror="http://mirror/", cache_dir=str(tmpdir))
    with nvd:
        assert nvd.meta.feed_timestamp["modified"] == "2026-09-24T14:00:03.1234567"
        assert not _load(nvd)
