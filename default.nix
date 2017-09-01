{ pkgs ? import <nixpkgs> { } }:

with pkgs.lib;

let
  # generate requirements.nix with
  # bin/pip freeze | egrep -v 'vulnix|pkg-resources' > requirements.txt
  # pypi2nix -V 3.5 -E libxml2 -E libxslt -r requirements.txt -v
  python = import ./requirements.nix { inherit pkgs; };
  version = pkgs.lib.removeSuffix "\n" (builtins.readFile ./VERSION);

in
python.mkDerivation {
  inherit version;
  name = "vulnix-${version}";

  src = builtins.filterSource
    (p: t: baseNameOf p != "result" && baseNameOf p != "__pycache__")
    ./.;

  buildInputs = [
    python.packages."pytest"
    python.packages."pytest-catchlog"
    python.packages."pytest-cov"
    python.packages."pytest-timeout"
  ];

  propagatedBuildInputs = [
    pkgs.nix
    python.packages."click"
    python.packages."colorama"
    python.packages."lxml"
    python.packages."PyYAML"
    python.packages."requests"
    python.packages."ZODB"
  ];

  checkPhase = ''
    export PYTHONPATH=src:$PYTHONPATH
    py.test
  '';
  dontStrip = true;

  meta = {
    description = "NixOS vulnerability scanner";
    homepage = https://github.com/flyingcircusio/vulnix;
    license = pkgs.lib.licenses.bsd3;
  };
}
