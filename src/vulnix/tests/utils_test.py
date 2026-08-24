import os
import subprocess
from unittest.mock import patch

import pytest

from vulnix.utils import (
    call,
    compare_versions,
    default_cache_dir,
    haskeys,
    split_components,
)


def test_default_cache_dir_unset():
    with patch.dict(os.environ, {}, clear=True):
        assert default_cache_dir() == "~/.cache/vulnix"


def test_default_cache_dir_empty():
    with patch.dict(os.environ, {"XDG_CACHE_HOME": ""}):
        assert default_cache_dir() == "~/.cache/vulnix"


def test_default_cache_dir_relative():
    with patch.dict(os.environ, {"XDG_CACHE_HOME": "relative-cache"}):
        assert default_cache_dir() == "~/.cache/vulnix"


def test_default_cache_dir_absolute():
    with patch.dict(os.environ, {"XDG_CACHE_HOME": "/tmp/xdgtest"}):
        assert default_cache_dir() == "/tmp/xdgtest/vulnix"


def test_compare_versions():
    """Tests from https://nixos.org/nix/manual/#ssec-version-comparisons"""
    assert -1 == compare_versions("1.0", "2.3")
    assert -1 == compare_versions("2.1", "2.3")
    assert 0 == compare_versions("2.3", "2.3")
    assert 1 == compare_versions("2.5", "2.3")
    assert 1 == compare_versions("3.1", "2.3")
    assert 1 == compare_versions("2.3.1", "2.3")
    assert 1 == compare_versions("2.3.1", "2.3a")
    assert 1 == compare_versions("2.3", "2.3pre")
    assert -1 == compare_versions("2.3pre1", "2.3")
    assert -1 == compare_versions("2.3pre3", "2.3pre12")
    assert -1 == compare_versions("2.3a", "2.3c")
    assert -1 == compare_versions("2.3pre1", "2.3c")
    assert -1 == compare_versions("2.3pre1", "2.3q")


def test_split_components():
    assert ["2", "3", "pre", "1"] == list(split_components("2.3pre1"))
    assert ["2019", "11", "01"] == list(split_components("2019-11-01"))
    assert ["5", "1", "a", "lts"] == list(split_components("5.1a-lts"))


def test_haskeys():
    assert not haskeys({}, "foo")
    assert haskeys({"foo": 1}, "foo")
    assert not haskeys({"foo": 1}, "foo", "bar")
    assert haskeys({"foo": {"bar": 1}}, "foo", "bar")
    assert not haskeys({"foo": {"bar": 1}}, "foo", "baz")


def test_call_emits_failed_command_stderr(monkeypatch, capsys):
    def fake_check_output(cmd, stderr):
        stderr.write(b"nix failed")
        raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr("vulnix.utils.subprocess.check_output", fake_check_output)

    with pytest.raises(subprocess.CalledProcessError):
        call(["nix"])

    assert capsys.readouterr().err == "nix failed"


def test_call_can_suppress_failed_command_stderr(monkeypatch, capsys):
    def fake_check_output(cmd, stderr):
        stderr.write(b"nix failed")
        raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr("vulnix.utils.subprocess.check_output", fake_check_output)

    with pytest.raises(subprocess.CalledProcessError):
        call(["nix"], log_stderr=False)

    assert capsys.readouterr().err == ""
