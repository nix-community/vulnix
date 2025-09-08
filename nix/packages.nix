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
      prefix_path = with pkgs; [
        nix
      ];
      check_inputs = with pp; [
        pkgs.ronn
        freezegun
        pytest
        pytest-cov
      ];
      build_inputs = with pp; [
        click
        pyyaml
        requests
        setuptools
        toml
        zodb
      ];
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
          nativeCheckInputs = check_inputs;
          propagatedBuildInputs = build_inputs;
          makeWrapperArgs = [ "--prefix PATH : ${lib.makeBinPath prefix_path}" ];
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
      devShells.default = pkgs.mkShell rec {
        name = "vulnix-devshell";
        packages = [
          pkgs.python3.pkgs.pylint # for running pylint manually in devshell
          pkgs.ruff # for running ruff manually in devshell
          check_inputs
          build_inputs
        ];
        shellHook = ''
          export PATH=${lib.makeBinPath prefix_path}:$PATH
          export PYTHONPATH="$PYTHONPATH:$(pwd)/src"
        '';
      };
    };
}
