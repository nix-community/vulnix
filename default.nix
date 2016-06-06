{ pkgs ? import <nixpkgs> { } }:

let
  py = pkgs.python3Packages;
in
  py.buildPythonPackage rec {
    name = "vulnix";
	  src = ./.;
	  propagatedBuildInputs = with py; [
      flake8 pytest pyyaml requests2
    ];
  }
