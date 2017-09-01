{ pkgs, python }:

with pkgs.lib;

self: super: {

  pytest = python.overrideDerivation super.pytest (old: {
    propagatedBuildInputs = old.propagatedBuildInputs ++ [
      super.setuptools-scm
    ];
  });

  pytest-runner = python.overrideDerivation super.pytest-runner (old: {
    propagatedBuildInputs = old.propagatedBuildInputs ++ [
      super.setuptools-scm
    ];
  });

}
