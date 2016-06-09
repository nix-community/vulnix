{ pkgs ? import <nixpkgs> { } }:

let
  py = pkgs.python3Packages;
in
  py.buildPythonPackage rec {
    name = "vulnix";
	  src = ./.;
	  buildInputs = with py; [ covCore pytest pytestcov ];
	  propagatedBuildInputs = with py; [
      flake8 pyyaml requests2
    ];

    checkPhase = ''
    runHook preCheck
    ${py.pytest}/bin/py.test
    runHook postCheck
    '';
  }
