import os
from pathlib import Path

import pytest

from vulnix.derivation import Derive
from vulnix.nix import Store


@pytest.fixture(name="json")
def fixture_json():
    fixtures_path = Path(os.path.dirname(os.path.realpath(__file__))) / "fixtures"
    return (fixtures_path / "pkgs.json").open()


def test_load_json(json):
    s = Store(requisites=False)
    s.load_pkgs_json(json)
    assert s.derivations == set(
        [
            Derive(name="acpitool-0.5.1", patches="ac.patch battery.patch"),
            Derive(name="aespipe-2.4f"),
            Derive(name="boolector-3.0.0", patches="CVE-2019-7560.patch CVE-2019-7559"),
        ]
    )
