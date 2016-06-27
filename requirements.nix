{ system ? builtins.currentSystem
, nixpkgs ? <nixpkgs>
}:

let

  inherit (pkgs.stdenv.lib) fix' extends;

  pkgs = import nixpkgs { inherit system; };
  pythonPackages = pkgs.python35Packages;

  python = {
    interpreter = pythonPackages.python;
    mkDerivation = pythonPackages.buildPythonPackage;
    modules = pythonPackages.python.modules;
    overrideDerivation = drv: f: pythonPackages.buildPythonPackage (drv.drvAttrs // f drv.drvAttrs);
    pkgs = pythonPackages;
  };

  generated = import ./requirements_generated.nix { inherit pkgs python; };
  overrides = import ./requirements_override.nix { inherit pkgs python; };

in {
  pkgs = fix' (extends overrides generated);
  inherit python;
}
