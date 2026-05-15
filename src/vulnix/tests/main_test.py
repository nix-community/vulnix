import pytest
from click.testing import CliRunner

from vulnix.main import main


@pytest.mark.parametrize(
    ("option", "parameter"),
    [(None, "'[PATH]...'"), ("--profile", "'-p' / '--profile'")],
)
def test_cli_validation_allows_guest_paths(tmp_path, option, parameter):
    missing = str(tmp_path / "missing")
    scan_args = [missing] if option is None else [option, missing]
    runner = CliRunner()

    result = runner.invoke(main, ["--version", *scan_args])

    assert result.exit_code == 2
    assert f"Invalid value for {parameter}" in result.output
    assert f"Path '{missing}' does not exist." in result.output

    result = runner.invoke(main, ["--guest", str(tmp_path), "--version", *scan_args])

    assert result.exit_code == 0
    assert result.output.startswith("vulnix ")


def test_missing_guest_profile_fails_scan(tmp_path, caplog):
    runner = CliRunner()

    result = runner.invoke(main, ["--guest", str(tmp_path), "--profile", "/missing"])

    assert result.exit_code == 2
    assert "profile `/missing` does not exist" in caplog.text
