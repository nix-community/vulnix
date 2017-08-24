{ pkgs, python }:

with pkgs.lib;

self: super: {
  # BTrees = python.overrideDerivation super.BTrees (old: {
  #   propagatedBuildInputs = [
  #     self."coverage"
  #     self."persistent"
  #     self."transaction"
  #     self."zope.interface"
  #   ];
  # });
}
