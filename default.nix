{ pkgs ? import (builtins.fetchTarball "https://d3g5gsiof5omrk.cloudfront.net/nixos/16.09/nixos-16.09.1324.1dd0fb6/nixexprs.tar.xz") {}
}:

let
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
    python.packages."flake8"
    python.packages."pytest"
    python.packages."pytest-capturelog"
    python.packages."pytest-codecheckers"
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
    license = pkgs.lib.licenses.bsd2;
  };
}
