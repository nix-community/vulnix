# SPDX-FileCopyrightText: 2024 Technology Innovation Institute (TII)
# SPDX-License-Identifier: BSD-3-Clause
{ lib, ... }:
{
  perSystem =
    { self', ... }:
    {
      checks =
        # Force a build of all packages during a `nix flake check`
        with lib; mapAttrs' (n: nameValuePair "package-${n}") self'.packages;
    };
}
