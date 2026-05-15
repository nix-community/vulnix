import json as jsonlib
import logging
import os
import subprocess
from pathlib import Path

import pytest

from vulnix.derivation import Derive
from vulnix.nix import DeriverLookupError, Store

# pylint: disable=protected-access


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


@pytest.mark.parametrize(
    ("kwargs", "expected_log_stderr"),
    [({}, True), ({"log_stderr": False}, False)],
)
def test_call_nixlike_adds_guest_store_and_forwards_log_stderr(
    monkeypatch, tmp_path, kwargs, expected_log_stderr
):
    calls = []

    def fake_call(args, log_stderr=True):
        calls.append((args, log_stderr))
        return ""

    monkeypatch.setattr("vulnix.nix.call", fake_call)
    store = Store(requisites=False, guest=str(tmp_path))

    store._call_nixlike(["nix-store", "-q"], **kwargs)

    assert calls == [
        (
            ["nix-store", "-q", "--store", f"local?root={tmp_path}"],
            expected_log_stderr,
        )
    ]


def test_add_guest_profile_uses_host_path(monkeypatch, tmp_path):
    profile = "/nix/var/nix/profiles/default"
    host_profile = tmp_path / profile.removeprefix("/")
    host_profile.mkdir(parents=True)
    calls = []

    def fake_call_nixlike(args):
        calls.append(args)
        return ""

    store = Store(requisites=False, guest=str(tmp_path))
    monkeypatch.setattr(store, "_call_nixlike", fake_call_nixlike)

    store.add_profile(profile)

    assert calls == [["nix-env", "-q", "--out-path", "--profile", str(host_profile)]]


def test_find_deriver_supports_wrapped_show_derivation_json(monkeypatch):
    s = Store(requisites=False)
    drv_path = "/nix/store/good.drv"
    drv_name = "good.drv"
    monkeypatch.setattr(
        s,
        "_call_nix",
        lambda _args: jsonlib.dumps(
            {"version": 3, "derivations": {drv_name: {"name": "good"}}}
        ),
    )
    monkeypatch.setattr("vulnix.nix.p.exists", lambda path: path == drv_path)

    assert s._find_deriver("/nix/store/good-out", "unknown-deriver") == drv_path


def test_guest_path_scan_loads_guest_derivation(monkeypatch, tmp_path):
    output_path = tmp_path / "nix/store/pkg-out"
    drv_path = tmp_path / "nix/store/pkg.drv"
    output_path.mkdir(parents=True)
    drv_path.touch()
    loaded = []

    def fake_call_nixlike(args, **_kwargs):
        assert args == ["nix-store", "-qd", "/nix/store/pkg-out"]
        return "/nix/store/pkg.drv\n"

    def fake_load(path):
        loaded.append(path)
        return Derive(name="pkg")

    store = Store(requisites=False, guest=str(tmp_path))
    monkeypatch.setattr(store, "_call_nixlike", fake_call_nixlike)
    monkeypatch.setattr("vulnix.nix.load", fake_load)

    store.add_path("/nix/store/pkg-out")

    assert loaded == [str(drv_path)]


def test_find_deriver_suppresses_stderr_for_all_optional_queries(monkeypatch):
    store = Store(requisites=False)

    def fake_call_nixlike(args, log_stderr=True):
        assert args == ["nix-store", "-qd", "/nix/store/pkg-out"]
        assert log_stderr is False
        return "unknown-deriver\n"

    def fake_show_derivations(path, log_stderr=True):
        assert path == "/nix/store/pkg-out"
        assert log_stderr is False
        return {}

    monkeypatch.setattr(store, "_call_nixlike", fake_call_nixlike)
    monkeypatch.setattr(store, "_show_derivations", fake_show_derivations)

    with pytest.raises(DeriverLookupError):
        store._find_deriver("/nix/store/pkg-out", log_stderr=False)


def test_find_outputs_supports_wrapped_show_derivation_json(monkeypatch):
    s = Store(requisites=False)
    monkeypatch.setattr(
        s,
        "_call_nix",
        lambda _args: jsonlib.dumps(
            {
                "version": 3,
                "derivations": {"good.drv": {"outputs": {"out": {"path": "good-out"}}}},
            }
        ),
    )

    assert s._find_outputs("/nix/store/good.drv") == ["/nix/store/good-out"]


def test_add_profile_reevaluates_wrapped_deriver_lookup_errors(monkeypatch, tmp_path):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        jsonlib.dumps(
            {
                "elements": {
                    "pkg": {
                        "active": True,
                        "storePaths": ["/nix/store/pkg-out"],
                        "attrPath": "packages.x86_64-linux.pkg",
                        "url": "github:example/repo",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    s = Store(requisites=False)
    updated = []
    nix_calls = []
    reevaluated = False

    def fake_call_nix(args, **_kwargs):
        nonlocal reevaluated
        nix_calls.append(args)
        if args[:1] == ["eval"]:
            reevaluated = True
            return ""
        if args[:2] == ["derivation", "show"]:
            raise subprocess.CalledProcessError(1, args)
        raise AssertionError(f"unexpected nix command: {args}")

    def fake_call_nix_store(cmd, log_stderr=True):  # pylint: disable=unused-argument
        return "/nix/store/missing.drv\n"

    def fake_exists(path):
        return path in {
            str(manifest_path),
            "/nix/store/pkg-out",
        } or (reevaluated and path == "/nix/store/missing.drv")

    monkeypatch.setattr(s, "_call_nix", fake_call_nix)
    monkeypatch.setattr(s, "update", updated.append)
    monkeypatch.setattr("vulnix.nix.call", fake_call_nix_store)
    monkeypatch.setattr("vulnix.nix.p.exists", fake_exists)

    s.add_profile(str(tmp_path))

    assert nix_calls == [
        ["derivation", "show", "/nix/store/pkg-out"],
        ["eval", "github:example/repo#packages.x86_64-linux.pkg"],
    ]
    assert updated == ["/nix/store/missing.drv"]


def test_add_profile_reevaluates_missing_root_deriver_in_closure(monkeypatch, tmp_path):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        jsonlib.dumps(
            {
                "elements": {
                    "pkg": {
                        "active": True,
                        "storePaths": ["/nix/store/pkg-out"],
                        "attrPath": "packages.x86_64-linux.pkg",
                        "url": "github:example/repo",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    s = Store(requisites=False, closure=True)
    updated = []
    nix_calls = []
    reevaluated = False

    def fake_call_nix(args, **_kwargs):
        nonlocal reevaluated
        nix_calls.append(args)
        if args[:1] == ["eval"]:
            reevaluated = True
            return ""
        if args[:3] == ["path-info", "-r", "--json"]:
            return jsonlib.dumps(
                [
                    {
                        "path": "/nix/store/pkg-out",
                        "deriver": "/nix/store/missing.drv",
                    },
                ]
            )
        if args[:2] == ["derivation", "show"]:
            raise subprocess.CalledProcessError(1, args)
        raise AssertionError(f"unexpected nix command: {args}")

    def fake_exists(path):
        return path in {
            str(manifest_path),
            "/nix/store/pkg-out",
        } or (reevaluated and path == "/nix/store/missing.drv")

    monkeypatch.setattr(s, "_call_nix", fake_call_nix)
    monkeypatch.setattr(s, "update", updated.append)
    monkeypatch.setattr("vulnix.nix.p.exists", fake_exists)

    s.add_profile(str(tmp_path))

    assert nix_calls == [
        ["path-info", "-r", "--json", "/nix/store/pkg-out"],
        ["derivation", "show", "/nix/store/pkg-out"],
        ["eval", "github:example/repo#packages.x86_64-linux.pkg"],
        ["path-info", "-r", "--json", "/nix/store/pkg-out"],
    ]
    assert updated == ["/nix/store/missing.drv"]


def test_closure_requires_canonical_root_output_deriver(monkeypatch):
    s = Store(requisites=False, closure=True)

    def fake_call_nix(args, **_kwargs):
        if args[:3] == ["path-info", "-r", "--json"]:
            return jsonlib.dumps(
                [
                    {
                        "path": "/nix/store/root-out",
                        "deriver": "/nix/store/missing.drv",
                    },
                ]
            )
        if args[:2] == ["derivation", "show"]:
            raise subprocess.CalledProcessError(1, args)
        raise AssertionError(f"unexpected nix command: {args}")

    monkeypatch.setattr(s, "_call_nix", fake_call_nix)
    monkeypatch.setattr("vulnix.nix.p.exists", lambda path: path == "./result")
    monkeypatch.setattr(
        "vulnix.nix.p.realpath",
        lambda path: "/nix/store/root-out/bin/tool" if path == "./result" else path,
    )

    with pytest.raises(DeriverLookupError):
        s.add_path("./result")


def test_closure_requires_root_output_deriver_when_path_info_has_null_deriver(
    monkeypatch,
):
    s = Store(requisites=False, closure=True)

    def fake_call_nix(args, **_kwargs):
        if args[:3] == ["path-info", "-r", "--json"]:
            return jsonlib.dumps(
                [
                    {
                        "path": "/nix/store/root-out",
                        "deriver": None,
                    },
                ]
            )
        if args[:2] == ["derivation", "show"]:
            raise subprocess.CalledProcessError(1, args)
        raise AssertionError(f"unexpected nix command: {args}")

    monkeypatch.setattr(s, "_call_nix", fake_call_nix)
    monkeypatch.setattr(
        "vulnix.nix.p.exists", lambda path: path == "/nix/store/root-out"
    )

    with pytest.raises(DeriverLookupError):
        s.add_path("/nix/store/root-out")


def test_canonical_output_path_handles_store_subpaths_without_resolving(monkeypatch):
    monkeypatch.setattr(
        "vulnix.nix.p.realpath",
        lambda _path: pytest.fail("store paths should not be resolved"),
    )

    assert Store._canonical_output_path("/nix/store/root-out") == "/nix/store/root-out"
    assert (
        Store._canonical_output_path("/nix/store/root-out/bin/tool")
        == "/nix/store/root-out"
    )


def test_closure_skips_outputs_without_loadable_derivers(monkeypatch, caplog):
    s = Store(requisites=False, closure=True)
    updated = []

    def fake_call_nix(args, log_stderr=True):
        if args[:3] == ["path-info", "-r", "--json"]:
            return jsonlib.dumps(
                [
                    {
                        "path": "/nix/store/good-out",
                        "deriver": "/nix/store/good.drv",
                    },
                    {
                        "path": "/nix/store/missing-out",
                        "deriver": "/nix/store/missing.drv",
                    },
                ]
            )
        if args[:2] == ["derivation", "show"]:
            assert log_stderr is False
            return jsonlib.dumps(
                {
                    "version": 3,
                    "derivations": {"/nix/store/missing.drv": {"name": "missing"}},
                }
            )
        raise AssertionError(f"unexpected nix command: {args}")

    monkeypatch.setattr(s, "_call_nix", fake_call_nix)
    monkeypatch.setattr(s, "update", updated.append)
    monkeypatch.setattr(
        "vulnix.nix.p.exists",
        lambda path: path in {"/nix/store/target", "/nix/store/good.drv"},
    )

    with caplog.at_level(logging.DEBUG, logger="vulnix.nix"):
        s.add_path("/nix/store/target")

    assert updated == ["/nix/store/good.drv"]
    skipped = [
        record
        for record in caplog.records
        if "Skipping closure path without deriver" in record.message
    ]
    assert skipped
    assert all(record.levelno == logging.DEBUG for record in skipped)


def test_host_path_keeps_symlink_resolution_under_guest(tmp_path):
    cases = [
        (
            "relative-symlink",
            "/nix/var/nix/profiles/default",
            lambda guest: (
                (guest / "nix/var/nix/profiles").mkdir(parents=True),
                (guest / "nix/var/nix/profiles/default").symlink_to(
                    "../../../../../../etc/passwd"
                ),
            ),
            ("etc", "passwd"),
        ),
        (
            "absolute-symlink",
            "/nix/escape",
            lambda guest: (
                (guest / "nix").mkdir(),
                (guest / "nix/escape").symlink_to("/../../../etc/shadow"),
            ),
            ("etc", "shadow"),
        ),
        (
            "logical-dotdot",
            "/nix/../etc/passwd",
            lambda guest: None,
            ("etc", "passwd"),
        ),
        (
            "intermediate-symlink",
            "/nix/store/foo",
            lambda guest: (
                (guest / "nix").symlink_to("var"),
                (guest / "var/store").mkdir(parents=True),
            ),
            ("var", "store", "foo"),
        ),
        (
            "dot-components",
            "/nix/./var/../var/nix/profiles/default",
            lambda guest: (guest / "nix/var/nix/profiles").mkdir(parents=True),
            ("nix", "var", "nix", "profiles", "default"),
        ),
        (
            "symlink-chain",
            "/a/c",
            lambda guest: (
                (guest / "a").symlink_to("b"),
                (guest / "b").symlink_to("../../etc/chain"),
            ),
            ("etc", "chain", "c"),
        ),
    ]

    for name, logical, prepare, expected_parts in cases:
        guest = tmp_path / name
        guest.mkdir()
        if prepare is not None:
            prepare(guest)
        store = Store(requisites=False, guest=str(guest))
        assert store._host_path(logical) == str(guest.joinpath(*expected_parts))


def test_host_path_rejects_relative_guest_path(tmp_path):
    store = Store(requisites=False, guest=str(tmp_path))

    with pytest.raises(RuntimeError, match="must be absolute"):
        store._host_path("nix/store/pkg")


def test_guest_symlink_path_is_resolved_before_deriver_query(monkeypatch, tmp_path):
    guest = tmp_path / "guest"
    target = guest / "nix/store/system"
    link = guest / "nix/var/nix/gcroots/current-system"
    target.mkdir(parents=True)
    link.parent.mkdir(parents=True)
    link.symlink_to("/nix/store/system")

    store = Store(requisites=False, guest=str(guest))
    queried = []
    monkeypatch.setattr(store, "_find_deriver", queried.append)

    store.add_path("/nix/var/nix/gcroots/current-system")

    assert queried == ["/nix/store/system"]


def test_guest_symlink_path_is_resolved_before_closure_query(monkeypatch, tmp_path):
    guest = tmp_path / "guest"
    target = guest / "nix/store/system"
    link = guest / "nix/var/nix/gcroots/current-system"
    target.mkdir(parents=True)
    link.parent.mkdir(parents=True)
    link.symlink_to("/nix/store/system")

    store = Store(requisites=False, closure=True, guest=str(guest))
    queried = []

    def fake_call_nix(args, **_kwargs):
        queried.append(args)
        return "[]"

    monkeypatch.setattr(store, "_call_nix", fake_call_nix)

    store.add_path("/nix/var/nix/gcroots/current-system")

    assert queried == [["path-info", "-r", "--json", "/nix/store/system"]]
