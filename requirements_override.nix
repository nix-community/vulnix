{ pkgs, python }:

self: super: {
  "zc.recipe.egg" = null;
  "zc.buildout" = null;
  "PyYAML" = super."PyYAML".overrideDerivation (old: {
    propagatedBuildInputs = old.propagatedBuildInputs ++ [ pkgs.libyaml ];
  });
}
