{ pkgs, python }:

self: super: {

  "flake8" = python.overrideDerivation super."flake8" (old: {
    buildInputs = old.buildInputs ++ [ self."pytest-runner" ];
  });

  "mccabe" = python.overrideDerivation super."mccabe" (old: {
    buildInputs = old.buildInputs ++ [ self."pytest-runner" ];
  });

  "pytest-runner" = python.overrideDerivation super."pytest-runner" (old: {
    buildInputs = old.buildInputs ++ [ self."setuptools-scm" ];
  });

  "PyYAML" = python.overrideDerivation super."PyYAML" (old: {
    propagatedBuildInputs = old.propagatedBuildInputs ++ [ pkgs.libyaml ];
  });

}
