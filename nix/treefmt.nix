# SPDX-FileCopyrightText: 2024 Technology Innovation Institute (TII)
# SPDX-License-Identifier: BSD-3-Clause
{ inputs, ... }:
{
  imports = with inputs; [
    flake-root.flakeModule
    treefmt-nix.flakeModule
  ];
  perSystem =
    {
      config,
      pkgs,
      ...
    }:
    {
      treefmt = {
        config = {
          package = pkgs.treefmt;
          inherit (config.flake-root) projectRootFile;
          settings.formatter.black.options = [ "--line-length=90" ];
          programs = {
            black.enable = true; # lints python https://github.com/psf/black
            isort.enable = true; # sort python imports https://github.com/PyCQA/isort
            deadnix.enable = true; # removes dead nix code https://github.com/astro/deadnix
            nixfmt.enable = true; # nix formatter https://github.com/NixOS/nixfmt
            nixfmt.package = pkgs.nixfmt-rfc-style; # rfc-166 formatting conform version
            statix.enable = true; # prevents use of nix anti-patterns https://github.com/nerdypepper/statix
          };
        };
      };

      # configures treefmt as the program to use when invoke `nix fmt`
      formatter = config.treefmt.build.wrapper;
    };
}
