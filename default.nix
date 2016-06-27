{ system ? builtins.currentSystem
, nixpkgs ? builtins.fetchTarball "https://github.com/NixOS/nixpkgs-channels/archive/453086a15fc0db0c2bc17d98350b0632551cb0fe.tar.gz"
}:

let
  pkgs = import nixpkgs { inherit system; };
  pythonEnv = import ./requirements.nix { inherit system nixpkgs; };
  version = pkgs.lib.removeSuffix "\n" (builtins.readFile ./VERSION);
in pythonEnv.python.mkDerivation {
  name = "vulnix-${version}";
  src = ./.;
  buildInputs = [
    pythonEnv.pkgs."flake8"
    pythonEnv.pkgs."pytest"
    pythonEnv.pkgs."pytest-cov"
  ];
   propagatedBuildInputs = [
    pythonEnv.pkgs."PyYAML"
    pythonEnv.pkgs."requests"
  ];
  checkPhase = ''
    runHook preCheck
    py.test
    runHook postCheck
  '';
}