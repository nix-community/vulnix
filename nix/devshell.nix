# SPDX-FileCopyrightText: 2024 Technology Innovation Institute (TII)
# SPDX-License-Identifier: BSD-3-Clause
{
  perSystem = {
    pkgs,
    self',
    ...
  }: {
    devShells.default = pkgs.mkShell rec {
      name = "vulnix-devshell";
      packages =
        (with self'.packages; [
          vulnix.propagatedBuildInputs
          vulnix.nativeBuildInputs
        ]);

      shellHook = ''
        export PYTHONPATH="$PYTHONPATH:$(pwd)/src"
      '';
    };
  };
}