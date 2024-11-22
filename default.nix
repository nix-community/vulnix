{ nixpkgs ? <nixpkgs>
, pkgs ? import nixpkgs {}
, lib ? pkgs.lib
}:
# uses build in upstream nixpkgs
(pkgs.vulnix).overrideAttrs (
  old: rec {
    src = lib.cleanSource ./.;
    version = lib.removeSuffix "\n" (builtins.readFile ./VERSION);
    name = "vulnix-${version}";
  }
)
