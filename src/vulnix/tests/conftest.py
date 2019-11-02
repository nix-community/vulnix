from vulnix.whitelist import Whitelist
import pkg_resources
import pytest

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
