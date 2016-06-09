with import <nixpkgs> {};

(python3.buildEnv.override {
  extraLibs = with python3Packages;
    [ flake8 covCore pytest pytestcov pyyaml requests2 ];
}).env
