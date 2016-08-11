{ pkgs ? import (builtins.fetchTarball "https://github.com/NixOS/nixpkgs-channels/archive/453086a15fc0db0c2bc17d98350b0632551cb0fe.tar.gz") {}
}:

let
  python = import ./requirements.nix { inherit pkgs; };
  version = pkgs.lib.removeSuffix "\n" (builtins.readFile ./VERSION);
in python.mkDerivation {
  name = "vulnix-${version}";
  src = ./.;
  buildInputs = [
    python.pkgs."flake8"
    python.pkgs."pytest"
    python.pkgs."pytest-capturelog"
    python.pkgs."pytest-codecheckers"
    python.pkgs."pytest-cov"
    python.pkgs."pytest-timeout"
  ];
   propagatedBuildInputs = [
    python.pkgs."click"
    python.pkgs."colorama"
    python.pkgs."PyYAML"
    python.pkgs."requests"
  ];
  checkPhase = ''
    runHook preCheck
    py.test
    runHook postCheck
  '';
}
