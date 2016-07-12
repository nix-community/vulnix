{ supportedSystems ? [ "x86_64-linux" ] }:

let
  pkgs = import <nixpkgs> {};

  buildFor = systems:
    builtins.listToAttrs (map (system:
      { name = system;
        value = import ./default.nix { pkgs = import pkgs.path { inherit system; }; };
      }) systems);

  version = pkgs.lib.removeSuffix "\n" (
    builtins.head (pkgs.lib.splitString "\n" (
      builtins.readFile ./VERSION)));

  jobs = {

    tarball = pkgs.stdenv.mkDerivation {
      name = "vulnix-${version}-tarball";
      src = ./.;
      buildInputs = with pkgs.python3Packages; [ python setuptools ];
      buildPhase = ''
        python3 setup.py sdist --formats=gztar
      '';
      installPhase = ''
        mkdir -p $out $out/nix-support
        mv dist/vulnix-${version}.tar.gz $out/
        echo "file source-dist $out/vulnix-${version}.tar.gz" > $out/nix-support/hydra-build-products
      '';
    };

    build = buildFor supportedSystems;

    release = pkgs.releaseTools.aggregate {
      name = "vulnix-${version}";
      meta.description = "Aggregate job containing the release-critical jobs.";
      constituents = [ jobs.tarball ] ++
        (map (x: builtins.attrValues x) [ jobs.build ]);
    };

  };

in jobs
