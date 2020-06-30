{ nixpkgs ? <nixpkgs>
, pkgs ? import nixpkgs {}
, lib ? pkgs.lib
}:

# uses build in upstream nixpkgs
(pkgs.callPackage "${nixpkgs}/pkgs/tools/security/vulnix" {
  python3Packages = pkgs.python37Packages;
}).overrideAttrs (
  old: rec {
    src = lib.cleanSource ./.;
    version = lib.removeSuffix "\n" (builtins.readFile ./VERSION);
    name = "vulnix-${version}";
  }
)
