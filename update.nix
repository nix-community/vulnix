{ pkgs ? import (builtins.fetchTarball "https://d3g5gsiof5omrk.cloudfront.net/nixos/16.09/nixos-16.09.1324.1dd0fb6/nixexprs.tar.xz") {}
}:

pkgs.stdenv.mkDerivation {
  name = "update-vulnix";
  buildCommand = ''
    echo "+--------------------------------------------------------+"
    echo "| Not possible to update repositories using \`nix-build\`. |"
    echo "|         Please run \`nix-shell update.nix\`.             |"
    echo "+--------------------------------------------------------+"
    exit 1
  '';
  shellHook = ''
    export HOME=$PWD
    ${pkgs.pypi2nix}/bin/pypi2nix -V 3.4 \
            -b buildout.cfg \
            -E "libxml2 libxslt" \
            -e pytest-runner \
            -e setuptools-scm \
            -v
    echo "Packages updated!"
    exit
  '';
}
