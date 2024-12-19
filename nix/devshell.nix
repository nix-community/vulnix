# SPDX-FileCopyrightText: 2024 Technology Innovation Institute (TII)
# SPDX-License-Identifier: BSD-3-Clause
{
  perSystem =
    {
      pkgs,
      self',
      ...
    }:
    {
      devShells.default = pkgs.mkShell rec {
        name = "vulnix-devshell";
        packages = with self'.packages; [
          pkgs.python3.pkgs.pylint # for running pylint manually in devshell
          vulnix.propagatedBuildInputs
          vulnix.nativeBuildInputs
        ];

        shellHook = ''
          export PYTHONPATH="$PYTHONPATH:$(pwd)/src"
        '';
      };
    };
}
