{ pkgs ? import <nixpkgs> {}
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
    ${pkgs.pypi2nix}/bin/pypi2nix -V 3.5 \
            -b buildout.cfg \
            -e pytest-runner \
            -e setuptools-scm \
            -v
    echo "Packages updated!"
    exit
  '';
}