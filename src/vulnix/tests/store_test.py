from vulnix.nix import Store
from vulnix.derivation import Derive
import pkg_resources
import pytest


@pytest.fixture
def json():
    return pkg_resources.resource_stream(
        'vulnix', 'tests/fixtures/pkgs.json')


def test_load_json(json):
    s = Store(requisites=False)
    s.load_pkgs_json(json)
    assert s.derivations == set([
        Derive(name="acpitool-0.5.1", patches="ac.patch battery.patch"),
        Derive(name="aespipe-2.4f"),
        Derive(name="boolector-3.0.0",
               patches="CVE-2019-7560.patch CVE-2019-7559")
    ])
