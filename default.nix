{ nixpkgs ? <nixpkgs>
, pkgs ? import nixpkgs {}
, lib ? pkgs.lib
}:

# uses build in upstream nixpkgs
(pkgs.callPackage "${nixpkgs}/pkgs/tools/security/vulnix" {
  pythonPackages = pkgs.python3Packages;
}).overrideAttrs (
  old: {
    src = lib.cleanSource ./.;
  }
)
