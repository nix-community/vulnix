# SPDX-FileCopyrightText: 2024 Technology Innovation Institute (TII)
# SPDX-License-Identifier: BSD-3-Clause
{ lib, self, ... }:
{
  perSystem =
    { pkgs, self', ... }:
    {
      checks = {
        pylint =
          pkgs.runCommandLocal "pylint"
            {
              nativeBuildInputs = [ self'.devShells.default.nativeBuildInputs ];
            }
            ''
              cd ${self.outPath}
              export HOME=/tmp
              pylint \
                $(find . -name "*.py") \
                --reports n \
                --enable=useless-suppression \
                --disable=missing-function-docstring \
                --disable=missing-module-docstring \
                --disable=missing-class-docstring
              touch $out
            '';
      }
      //
        # Force a build of all packages during a `nix flake check`
        (with lib; mapAttrs' (n: nameValuePair "package-${n}") self'.packages);
    };
}
