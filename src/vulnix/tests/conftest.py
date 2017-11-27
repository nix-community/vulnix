from vulnix.nvd import NVD, Archive, decompress
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
