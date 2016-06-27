{ pkgs, python }:

self: {
  "colorama" = python.mkDerivation {
    name = "colorama-0.3.7";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/cd/ac/228603eb4c2aa4c77e767f3d7165b3c9b3196367fa8e3a9131a87a41de5c/colorama-0.3.7.zip";
      md5 = "2ff79e6cbff3a30dfbed936d98d60f1e";
    };
    doCheck = false;
    propagatedBuildInputs = [  ];
     meta = {
       homepage = "";
       license = "BSD";
       description = "Cross-platform colored terminal text.";
     };
   };
  "click" = python.mkDerivation {
    name = "click-6.6";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/7a/00/c14926d8232b36b08218067bcd5853caefb4737cda3f0a47437151344792/click-6.6.tar.gz";
      md5 = "d0b09582123605220ad6977175f3e51d";
    };
    doCheck = false;
    propagatedBuildInputs = [  ];
     meta = {
       homepage = "";
       license = "";
       description = "A simple wrapper around optparse for powerful command line utilities.";
     };
   };
  "coverage" = python.mkDerivation {
    name = "coverage-4.0.3";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/76/b4/3777a6bae434240b1fcbbda6cb30085bd897b3519acfffea498ee9f41038/coverage-4.0.3.tar.gz";
      md5 = "c7d3db1882484022c81bf619be7b6365";
    };
    doCheck = false;
    propagatedBuildInputs = [  ];
     meta = {
       homepage = "";
       license = "Apache 2.0";
       description = "Code coverage measurement for Python";
     };
   };
  "mccabe" = python.mkDerivation {
    name = "mccabe-0.4.0";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/f6/e7/54461a958bb8b16f8db5f849d5d08b7d74153e064ac385fb68ff09f0bd27/mccabe-0.4.0.tar.gz";
      md5 = "8c425db05f310adcd4bb174b991f26f5";
    };
    doCheck = false;
    propagatedBuildInputs = [  ];
     meta = {
       homepage = "";
       license = "Expat license";
       description = "McCabe checker, plugin for flake8";
     };
   };
  "apipkg" = python.mkDerivation {
    name = "apipkg-1.4";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/32/37/6ce6dbaa8035730efa95e60b09498ec17000d137742391ff46974d9ef859/apipkg-1.4.tar.gz";
      md5 = "17e5668601a2322aff41548cb957e7c8";
    };
    doCheck = false;
    propagatedBuildInputs = [  ];
     meta = {
       homepage = "";
       license = "MIT License";
       description = "apipkg: namespace control and lazy-import mechanism";
     };
   };
  "pytest-codecheckers" = python.mkDerivation {
    name = "pytest-codecheckers-0.2";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/53/09/263669db13955496e77017f389693c1e1dd77d98fd4afd51b133162e858f/pytest-codecheckers-0.2.tar.gz";
      md5 = "5e7449fc6cd02d35cc11e21709ce1357";
    };
    doCheck = false;
    propagatedBuildInputs = [ self."pep8" self."py" self."pyflakes" ];
     meta = {
       homepage = "";
       license = "";
       description = "pytest plugin to add source code sanity checks (pep8 and friends)";
     };
   };
  "pytest" = python.mkDerivation {
    name = "pytest-2.9.1";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/5e/f0/75c5cee17575bef459c916b6276bd9ad56944836bb0d9e36dd05704e7f35/pytest-2.9.1.tar.gz";
      md5 = "05165740ea50928e4e971378630163ec";
    };
    doCheck = false;
    propagatedBuildInputs = [ self."py" self."colorama" ];
     meta = {
       homepage = "";
       license = "MIT license";
       description = "pytest: simple powerful testing with Python";
     };
   };
  "pytest-capturelog" = python.mkDerivation {
    name = "pytest-capturelog-0.7";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/35/e9/6051b5bb65ad5049d5eb60127d34c63ba724e17acf8b1f2f2e0755131b6c/pytest-capturelog-0.7.tar.gz";
      md5 = "cfeac23d8ed254deaeb50a8c0aa141e9";
    };
    doCheck = false;
    propagatedBuildInputs = [ self."py" ];
     meta = {
       homepage = "";
       license = "MIT License";
       description = "py.test plugin to capture log messages";
     };
   };
  "flake8" = python.mkDerivation {
    name = "flake8-2.5.4";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/60/4a/7b0ac4920af5673380b7079ba2f7580a8645790c7718881082c0d918b8b4/flake8-2.5.4.tar.gz";
      md5 = "a4585b3569b95c3f66acb8294a7f06ef";
    };
    doCheck = false;
    propagatedBuildInputs = [ self."mccabe" self."pyflakes" self."pep8" ];
     meta = {
       homepage = "";
       license = "MIT";
       description = "the modular source code checker: pep8, pyflakes and co";
     };
   };
  "pep8" = python.mkDerivation {
    name = "pep8-1.7.0";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/3e/b5/1f717b85fbf5d43d81e3c603a7a2f64c9f1dabc69a1e7745bd394cc06404/pep8-1.7.0.tar.gz";
      md5 = "2b03109b0618afe3b04b3e63b334ac9d";
    };
    doCheck = false;
    propagatedBuildInputs = [  ];
     meta = {
       homepage = "";
       license = "Expat license";
       description = "Python style guide checker";
     };
   };
  "pytest-cov" = python.mkDerivation {
    name = "pytest-cov-2.2.1";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/39/07/bdd2d985ae7ac726cc5e7a6a343b585570bf1f9f7cb297a9cd58a60c7c89/pytest-cov-2.2.1.tar.gz";
      md5 = "d4c65c5561343e6c6a583d5fd29e6a63";
    };
    doCheck = false;
    propagatedBuildInputs = [ self."pytest" self."coverage" ];
     meta = {
       homepage = "";
       license = "MIT";
       description = "Pytest plugin for measuring coverage.";
     };
   };
  "PyYAML" = python.mkDerivation {
    name = "PyYAML-3.11";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/04/60/abfb3a665ee0569b60c89148b7187ddd8a36cb65e254fba945ae1315645d/PyYAML-3.11.zip";
      md5 = "89cbc92cda979042533b640b76e6e055";
    };
    doCheck = false;
    propagatedBuildInputs = [  ];
     meta = {
       homepage = "";
       license = "MIT";
       description = "YAML parser and emitter for Python";
     };
   };
  "zc.buildout" = python.mkDerivation {
    name = "zc.buildout-2.5.2";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/ec/a1/60214738d5dcb199ad97034ecf349d18f3ab69659df827a5e182585bfe48/zc.buildout-2.5.2.tar.gz";
      md5 = "06a21fb02528c07aa0db31de0389a244";
    };
    doCheck = false;
    propagatedBuildInputs = [  ];
     meta = {
       homepage = "";
       license = "ZPL 2.1";
       description = "System for managing development buildouts";
     };
   };
  "pyflakes" = python.mkDerivation {
    name = "pyflakes-1.0.0";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/45/24/6bc038f3422bab08c24173c1990a56e9eb0c4582a9b202858a33f8aefeb8/pyflakes-1.0.0.tar.gz";
      md5 = "914621d4c9546248419b435dd358eb6a";
    };
    doCheck = false;
    propagatedBuildInputs = [  ];
     meta = {
       homepage = "";
       license = "MIT";
       description = "passive checker of Python programs";
     };
   };
  "py" = python.mkDerivation {
    name = "py-1.4.31";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/f4/9a/8dfda23f36600dd701c6722316ba8a3ab4b990261f83e7d3ffc6dfedf7ef/py-1.4.31.tar.gz";
      md5 = "5d2c63c56dc3f2115ec35c066ecd582b";
    };
    doCheck = false;
    propagatedBuildInputs = [  ];
     meta = {
       homepage = "";
       license = "MIT license";
       description = "library with cross-python path, ini-parsing, io, code, log facilities";
     };
   };
  "execnet" = python.mkDerivation {
    name = "execnet-1.4.1";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/eb/ee/43729e7dee8772e69b3b01715ab9742790be2eace2d18cf53d219b9c31f8/execnet-1.4.1.tar.gz";
      md5 = "0ff84b6c79d0dafb7e2971629c4d127a";
    };
    doCheck = false;
    propagatedBuildInputs = [ self."apipkg" ];
     meta = {
       homepage = "";
       license = "MIT";
       description = "execnet: rapid multi-Python deployment";
     };
   };
  "requests" = python.mkDerivation {
    name = "requests-2.10.0";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/49/6f/183063f01aae1e025cf0130772b55848750a2f3a89bfa11b385b35d7329d/requests-2.10.0.tar.gz";
      md5 = "a36f7a64600f1bfec4d55ae021d232ae";
    };
    doCheck = false;
    propagatedBuildInputs = [  ];
     meta = {
       homepage = "";
       license = "Apache 2.0";
       description = "Python HTTP for Humans.";
     };
   };
  "zc.recipe.egg" = python.mkDerivation {
    name = "zc.recipe.egg-2.0.3";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/08/5e/ade683d229d77ed457017145672f1be4fd98be60f1a5344109a4e66a7d54/zc.recipe.egg-2.0.3.tar.gz";
      md5 = "69a8ce276029390a36008150444aa0b4";
    };
    doCheck = false;
    propagatedBuildInputs = [ self."zc.buildout" ];
     meta = {
       homepage = "";
       license = "ZPL 2.1";
       description = "Recipe for installing Python package distributions as eggs";
     };
   };
  "pytest-timeout" = python.mkDerivation {
    name = "pytest-timeout-1.0.0";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/cf/92/ab29b9baa54d47dfd50e43be35577de9af4e7ebf27d29f546ddeb6c3b6f5/pytest-timeout-1.0.0.tar.gz";
      md5 = "f9f162bd079689980b5614673ddfdae4";
    };
    doCheck = false;
    propagatedBuildInputs = [ self."pytest" ];
     meta = {
       homepage = "";
       license = "MIT";
       description = "py.test plugin to abort hanging tests";
     };
   };
  "pytest-cache" = python.mkDerivation {
    name = "pytest-cache-1.0";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/d1/15/082fd0428aab33d2bafa014f3beb241830427ba803a8912a5aaeaf3a5663/pytest-cache-1.0.tar.gz";
      md5 = "e51ff62fec70a1fd456d975ce47977cd";
    };
    doCheck = false;
    propagatedBuildInputs = [ self."execnet" self."pytest" ];
     meta = {
       homepage = "";
       license = "";
       description = "pytest plugin with mechanisms for caching across test runs";
     };
   };
}
