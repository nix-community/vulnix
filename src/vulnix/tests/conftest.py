from vulnix.nvd import NVD, Archive, decompress
from vulnix.whitelist import Whitelist
import pkg_resources
import pytest


@pytest.fixture
def nvd_modified(tmpdir):
    nvd = NVD(cache_dir=str(tmpdir))
    a = Archive('Modified')
    with open(pkg_resources.resource_filename(
            'vulnix', 'tests/nvdcve-2.0-Modified.xml.gz'), 'rb') as f:
        a.parse(decompress(f, str(tmpdir)))
    nvd.add(a)
    return nvd


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
