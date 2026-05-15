import json
import logging
import os
import os.path as p
import subprocess

from .derivation import Derive, SkipDrv, load
from .utils import call

_log = logging.getLogger(__name__)
STORE_DIR = "/nix/store"


class DeriverLookupError(RuntimeError):
    """A store path has no loadable derivation metadata."""


class Store:
    def __init__(self, requisites=True, closure=False, guest=None):
        self.requisites = requisites
        self.closure = closure
        self.guest = p.abspath(guest) if guest else None
        self.derivations = set()
        self.experimental_flag_needed = None

    def add_gc_roots(self):
        """Add derivations found for all live GC roots.

        Note that this usually includes old system versions.
        """
        _log.debug("Loading all live derivations")
        for d in self._call_nixlike(["nix-store", "--gc", "--print-live"]).splitlines():
            self.update(d)

    # pylint: disable=too-many-branches
    def add_profile(self, profile):
        """Add derivations found in this nix profile."""
        host_profile = self._host_path(profile)
        json_manifest_path = p.join(host_profile, "manifest.json")
        if p.exists(json_manifest_path):
            _log.debug("Loading derivations from %s", json_manifest_path)
            with open(json_manifest_path, "r", encoding="utf-8") as f:
                json_manifest = json.load(f)
            elements = json_manifest["elements"]
            # nix profile elements in manifest.json can be in two
            # different formats: https://github.com/NixOS/nix/pull/9656
            if isinstance(elements, dict):
                for name in elements:
                    element = elements[name]
                    if not element["active"]:
                        continue
                    for path in element["storePaths"]:
                        try:
                            self.add_path(path)
                        except (subprocess.CalledProcessError, DeriverLookupError):
                            attr_path = element["attrPath"]
                            if not attr_path or not element["url"]:
                                raise
                            _log.warning(
                                "Re-evaluating derivation for %s via %s#%s",
                                name,
                                element["url"],
                                attr_path,
                            )
                            self._call_nix(["eval", element["url"] + "#" + attr_path])
                            self.add_path(path)
            if isinstance(elements, list):
                for element in elements:
                    if not element["active"]:
                        continue
                    for path in element["storePaths"]:
                        self.add_path(path)
        else:
            if not p.exists(host_profile):
                raise RuntimeError(f"profile `{profile}` does not exist")
            _log.debug("Loading derivations from user profile %s", profile)
            for line in self._call_nixlike(
                ["nix-env", "-q", "--out-path", "--profile", host_profile]
            ).splitlines():
                self.add_path(line.split()[1])

    def _call_nixlike(self, args, log_stderr=True):
        if self.guest is not None:
            args += ["--store", f"local?root={self.guest}"]
        return call(args, log_stderr=log_stderr)

    def _call_nix(self, args, log_stderr=True):
        if self.experimental_flag_needed is None:
            self.experimental_flag_needed = "--experimental-features" in call(
                ["nix", "--help"]
            )

        if self.experimental_flag_needed:
            return self._call_nixlike(
                ["nix", "--experimental-features", "nix-command flakes"] + args,
                log_stderr=log_stderr,
            )
        return self._call_nixlike(["nix"] + args, log_stderr=log_stderr)

    def _host_path(self, path):
        if self.guest is None:
            return path
        if not p.isabs(path):
            raise RuntimeError(f"path `{path}` must be absolute")

        # Path relative to the guest root (logical "/" == self.guest).
        remaining = path.lstrip("/")
        for _ in range(16):  # Reject paths requiring 16 or more symlink rewrites.
            parts = []
            while remaining:
                component, _, remaining = remaining.partition("/")
                if component == "..":
                    # At logical root, ".." is a no-op (/.. == /).
                    if parts:
                        parts.pop()
                elif component and component != ".":
                    parts.append(component)
                    host_path = p.join(self.guest, *parts)
                    if p.islink(host_path):
                        link_target = os.readlink(host_path)
                        if p.isabs(link_target):
                            base = link_target.lstrip("/")
                        elif parts[:-1]:
                            base = f"{'/'.join(parts[:-1])}/{link_target}"
                        else:
                            base = link_target
                        if remaining and not remaining.startswith("/"):
                            remaining = "/" + remaining
                        remaining = base + remaining
                        break  # Restart walk with rewritten remaining path.
            else:
                return p.join(self.guest, *parts)
        raise RuntimeError(f"symlink chain is too deep: {path}")

    @staticmethod
    def _absolute_store_path(path):
        if not path or not isinstance(path, str) or path.startswith("/"):
            return path
        return p.join(STORE_DIR, path)

    @staticmethod
    def _canonical_output_path(path):
        if not path or not isinstance(path, str):
            return path
        if not path.startswith(STORE_DIR + "/"):
            path = p.realpath(path)
        if not path.startswith(STORE_DIR + "/"):
            return path
        return p.join(STORE_DIR, path[len(STORE_DIR) + 1 :].split("/", 1)[0])

    def _normalize_derivations(self, derivations):
        normalized = {}
        for drv_path, drv in derivations.items():
            drv_path = self._absolute_store_path(drv_path)
            outputs = drv.get("outputs", {})
            for output in outputs.values():
                output["path"] = self._absolute_store_path(output.get("path"))
            normalized[drv_path] = drv
        return normalized

    def _show_derivations(self, path, log_stderr=True):
        """Return derivation metadata from all supported Nix JSON shapes."""
        try:
            args = ["derivation", "show", path]
            if log_stderr:
                data = json.loads(self._call_nix(args))
            else:
                data = json.loads(self._call_nix(args, log_stderr=False))
        except subprocess.CalledProcessError as error:
            raise DeriverLookupError(
                f"Cannot determine deriver for path `{path}`"
            ) from error
        if isinstance(data, dict) and isinstance(data.get("derivations"), dict):
            data = data["derivations"]
        if isinstance(data, dict):
            return self._normalize_derivations(data)
        raise DeriverLookupError(
            f"Unexpected `nix derivation show` JSON for path `{path}`"
        )

    def _find_deriver(self, path, qpi_deriver="undef", log_stderr=True):
        if not path:
            return None
        if path.endswith(".drv"):
            return path
        # Deriver from QueryPathInfo
        if qpi_deriver == "undef":
            qpi_deriver = self._call_nixlike(
                ["nix-store", "-qd", path], log_stderr=log_stderr
            ).strip()
        _log.debug("qpi_deriver: %s", qpi_deriver)
        if (
            qpi_deriver
            and qpi_deriver != "unknown-deriver"
            and p.exists(self._host_path(qpi_deriver))
        ):
            return qpi_deriver
        # Deriver from QueryValidDerivers
        qvd_derivations = self._show_derivations(path, log_stderr=log_stderr)
        qvd_deriver = next(iter(qvd_derivations), None)
        _log.debug("qvd_deriver: %s", qvd_deriver)
        if qvd_deriver and p.exists(self._host_path(qvd_deriver)):
            return qvd_deriver

        error = ""
        if qpi_deriver and qpi_deriver != "unknown-deriver":
            error += f"Deriver `{qpi_deriver}` does not exist.  "
        if qvd_deriver and qvd_deriver != qpi_deriver:
            error += f"Deriver `{qvd_deriver}` does not exist.  "
        if error:
            raise DeriverLookupError(error + f"Couldn't find deriver for path `{path}`")
        raise DeriverLookupError(
            "Cannot determine deriver. Is this really a path into the nix store?", path
        )

    def _find_outputs(self, path):
        if not path.endswith(".drv"):
            return [path]

        result = []
        for drv in self._show_derivations(path).values():
            for output in drv.get("outputs").values():
                result.append(output.get("path"))
        return result

    def _update_closure_candidate(self, outpath, info, required=False):
        try:
            candidate = self._find_deriver(
                outpath,
                qpi_deriver=info.get("deriver"),
                log_stderr=required,
            )
        except DeriverLookupError as error:
            if required:
                raise
            _log.debug("Skipping closure path without deriver: %s", error)
            return
        self.update(candidate)

    def add_path(self, path):
        # pylint: disable=too-many-branches
        """Add the closure of all derivations referenced by a store path."""
        host_path = self._host_path(path)
        if not p.exists(host_path):
            raise RuntimeError(
                f"path `{host_path}` does not exist - cannot load "
                "derivations referenced from it"
            )
        if self.guest is not None:
            path = "/" + p.relpath(host_path, self.guest)
        _log.debug('Loading derivations referenced by "%s"', host_path)

        if self.closure:
            for output in self._find_outputs(path):
                root_output = self._canonical_output_path(output)
                data = json.loads(self._call_nix(["path-info", "-r", "--json", output]))
                if not data:
                    continue
                # 'nix path-info -r --json' can return two different json
                # output format: https://github.com/NixOS/nix/pull/9242
                if isinstance(data, dict):
                    for outpath, info in data.items():
                        self._update_closure_candidate(
                            outpath, info, required=outpath == root_output
                        )
                elif isinstance(data, list):
                    for info in data:
                        outpath = info.get("path")
                        self._update_closure_candidate(
                            outpath, info, required=outpath == root_output
                        )
                else:
                    _log.warning("path-info for '%s' returned unexpected json", output)
        else:
            deriver = self._find_deriver(path)
            if self.requisites:
                for candidate in self._call_nixlike(
                    ["nix-store", "-qR", deriver]
                ).splitlines():
                    self.update(candidate)
            else:
                self.update(deriver)

    def update(self, drv_path):
        if not drv_path or not drv_path.endswith(".drv"):
            return
        try:
            drv_obj = load(self._host_path(drv_path))
        except SkipDrv:
            return
        self.derivations.add(drv_obj)

    def load_pkgs_json(self, json_fobj):
        for pkg in json.load(json_fobj).values():
            try:
                patches = pkg["patches"]
                if "known_vulnerabilities" in pkg:
                    patches.extend(pkg["known_vulnerabilities"])
                self.derivations.add(
                    Derive(name=pkg["name"], patches=" ".join(patches))
                )
            except SkipDrv:
                _log.debug("skipping: %s", pkg)
                continue
