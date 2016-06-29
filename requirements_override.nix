{ pkgs, python }:

self: super: {
  "PyYAML" = super."PyYAML".overrideDerivation (old: {
    propagatedBuildInputs = old.propagatedBuildInputs ++ [ pkgs.libyaml ];
  });
}
