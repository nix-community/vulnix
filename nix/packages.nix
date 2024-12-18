# SPDX-FileCopyrightText: 2024 Technology Innovation Institute (TII)
# SPDX-License-Identifier: BSD-3-Clause
{
  perSystem =
    {
      pkgs,
      lib,
      ...
    }:
    let
      pp = pkgs.python3Packages;
    in
    {
      packages = rec {
        default = vulnix;

        vulnix = pp.buildPythonPackage {
          pname = "vulnix";
          version = pkgs.lib.removeSuffix "\n" (builtins.readFile ../VERSION);
          format = "setuptools";

          src = lib.cleanSource ../.;

          pythonImportsCheck = [ "vulnix" ];

          outputs = [
            "out"
            "doc"
            "man"
          ];

          nativeBuildInputs = [ pkgs.ronn ];

          nativeCheckInputs = with pp; [
            freezegun
            pytest
            pytest-cov
          ];

          propagatedBuildInputs = with pp; [
            click
            pyyaml
            requests
            setuptools
            toml
            zodb
          ];

          makeWrapperArgs = [
            "--prefix PATH : ${
              lib.makeBinPath (
                with pkgs;
                [
                  nix
                ]
              )
            }"
          ];

          postBuild = "make -C doc";

          checkPhase = "pytest src/vulnix";

          postInstall = ''
            install -D -t $doc/share/doc/vulnix README.rst CHANGES.rst
            gzip $doc/share/doc/vulnix/*.rst
            install -D -t $man/share/man/man1 doc/vulnix.1
            install -D -t $man/share/man/man5 doc/vulnix-whitelist.5
          '';

          dontStrip = true;
        };
      };
    };
}
