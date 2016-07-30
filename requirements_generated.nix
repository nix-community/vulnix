# generated using pypi2nix tool (version: 1.4.0dev)
#
# COMMAND:
#   pypi2nix -V 3.5 -e . -e flake8 -e pytest -e pytest-cache -e pytest-capturelog -e pytest-codecheckers -e pytest-timeout -e pytest-cov -e pytest-runner -e setuptools-scm
#

{ pkgs, python, commonBuildInputs ? [], commonDoCheck ? false }:

self: {

  "PyYAML" = python.mkDerivation {
    name = "PyYAML-3.11";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/75/5e/b84feba55e20f8da46ead76f14a3943c8cb722d40360702b2365b91dec00/PyYAML-3.11.tar.gz";
      sha256= "c36c938a872e5ff494938b33b14aaa156cb439ec67548fcab3535bb78b0846e8";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [ ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = licenses.mit;
      description = "YAML parser and emitter for Python";
    };
    passthru.top_level = false;
  };



  "apipkg" = python.mkDerivation {
    name = "apipkg-1.4";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/32/37/6ce6dbaa8035730efa95e60b09498ec17000d137742391ff46974d9ef859/apipkg-1.4.tar.gz";
      sha256= "2e38399dbe842891fe85392601aab8f40a8f4cc5a9053c326de35a1cc0297ac6";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [ ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = licenses.mit;
      description = "apipkg: namespace control and lazy-import mechanism";
    };
    passthru.top_level = false;
  };



  "click" = python.mkDerivation {
    name = "click-6.6";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/7a/00/c14926d8232b36b08218067bcd5853caefb4737cda3f0a47437151344792/click-6.6.tar.gz";
      sha256= "cc6a19da8ebff6e7074f731447ef7e112bd23adf3de5c597cf9989f2fd8defe9";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [ ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = "";
      description = "A simple wrapper around optparse for powerful command line utilities.";
    };
    passthru.top_level = false;
  };



  "colorama" = python.mkDerivation {
    name = "colorama-0.3.7";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/f0/d0/21c6449df0ca9da74859edc40208b3a57df9aca7323118c913e58d442030/colorama-0.3.7.tar.gz";
      sha256= "e043c8d32527607223652021ff648fbb394d5e19cba9f1a698670b338c9d782b";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [ ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = licenses.bsdOriginal;
      description = "Cross-platform colored terminal text.";
    };
    passthru.top_level = false;
  };



  "coverage" = python.mkDerivation {
    name = "coverage-4.2";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/53/fe/9e0fbdbca15c2c1253379c3a694f4315a420555e7874445b06edeaeacaea/coverage-4.2.tar.gz";
      sha256= "e312776d3ef04632ec742ce2d2b7048b635073e0245e4f44dfe8b08cc50ac656";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [ ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = licenses.asl20;
      description = "Code coverage measurement for Python";
    };
    passthru.top_level = false;
  };



  "execnet" = python.mkDerivation {
    name = "execnet-1.4.1";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/eb/ee/43729e7dee8772e69b3b01715ab9742790be2eace2d18cf53d219b9c31f8/execnet-1.4.1.tar.gz";
      sha256= "f66dd4a7519725a1b7e14ad9ae7d3df8e09b2da88062386e08e941cafc0ef3e6";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [
      self."apipkg"
    ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = licenses.mit;
      description = "execnet: rapid multi-Python deployment";
    };
    passthru.top_level = false;
  };



  "flake8" = python.mkDerivation {
    name = "flake8-3.0.3";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/e2/dd/cf299399dec65eed186509d625760195938e83d3bcf78f47d443d58aff7d/flake8-3.0.3.tar.gz";
      sha256= "fa8ebbdc9a78991af150b86cd0e3377361586ce7d1fed0079f0077f2ada227ec";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [
      self."mccabe"
      self."pycodestyle"
      self."pyflakes"
    ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = licenses.mit;
      description = "the modular source code checker: pep8, pyflakes and co";
    };
    passthru.top_level = false;
  };



  "mccabe" = python.mkDerivation {
    name = "mccabe-0.5.1";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/fd/7c/9cbdc4515bc26e8527d164fc5983308d721c685620ee1aa025a72c7f056f/mccabe-0.5.1.tar.gz";
      sha256= "8a30b9cb533b2bde819e7143bd56efc8b52e2fb9ed5ab0983cfd52ca596f88b2";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [ ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = "Expat license";
      description = "McCabe checker, plugin for flake8";
    };
    passthru.top_level = false;
  };



  "pep8" = python.mkDerivation {
    name = "pep8-1.7.0";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/3e/b5/1f717b85fbf5d43d81e3c603a7a2f64c9f1dabc69a1e7745bd394cc06404/pep8-1.7.0.tar.gz";
      sha256= "a113d5f5ad7a7abacef9df5ec3f2af23a20a28005921577b15dd584d099d5900";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [ ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = "Expat license";
      description = "Python style guide checker";
    };
    passthru.top_level = false;
  };



  "py" = python.mkDerivation {
    name = "py-1.4.31";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/f4/9a/8dfda23f36600dd701c6722316ba8a3ab4b990261f83e7d3ffc6dfedf7ef/py-1.4.31.tar.gz";
      sha256= "a6501963c725fc2554dabfece8ae9a8fb5e149c0ac0a42fd2b02c5c1c57fc114";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [ ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = "MIT license";
      description = "library with cross-python path, ini-parsing, io, code, log facilities";
    };
    passthru.top_level = false;
  };



  "pycodestyle" = python.mkDerivation {
    name = "pycodestyle-2.0.0";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/db/b1/9f798e745a4602ab40bf6a9174e1409dcdde6928cf800d3aab96a65b1bbf/pycodestyle-2.0.0.tar.gz";
      sha256= "37f0420b14630b0eaaf452978f3a6ea4816d787c3e6dcbba6fb255030adae2e7";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [ ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = "Expat license";
      description = "Python style guide checker";
    };
    passthru.top_level = false;
  };



  "pyflakes" = python.mkDerivation {
    name = "pyflakes-1.2.3";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/54/80/6a641f832eb6c6a8f7e151e7087aff7a7c04dd8b4aa6134817942cdda1b6/pyflakes-1.2.3.tar.gz";
      sha256= "2e4a1b636d8809d8f0a69f341acf15b2e401a3221ede11be439911d23ce2139e";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [ ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = licenses.mit;
      description = "passive checker of Python programs";
    };
    passthru.top_level = false;
  };



  "pytest" = python.mkDerivation {
    name = "pytest-2.9.2";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/f0/ee/6e2522c968339dca7d9abfd5e71312abeeb5ee902e09b4daf44f07b2f907/pytest-2.9.2.tar.gz";
      sha256= "12c18abb9a09a5b2802dba75c7a2d7d6c8c0f1258abd8243e7688415d87ad1d8";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [
      self."colorama"
      self."py"
    ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = "MIT license";
      description = "pytest: simple powerful testing with Python";
    };
    passthru.top_level = false;
  };



  "pytest-cache" = python.mkDerivation {
    name = "pytest-cache-1.0";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/d1/15/082fd0428aab33d2bafa014f3beb241830427ba803a8912a5aaeaf3a5663/pytest-cache-1.0.tar.gz";
      sha256= "be7468edd4d3d83f1e844959fd6e3fd28e77a481440a7118d430130ea31b07a9";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [
      self."execnet"
      self."pytest"
    ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = "";
      description = "pytest plugin with mechanisms for caching across test runs";
    };
    passthru.top_level = false;
  };



  "pytest-capturelog" = python.mkDerivation {
    name = "pytest-capturelog-0.7";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/35/e9/6051b5bb65ad5049d5eb60127d34c63ba724e17acf8b1f2f2e0755131b6c/pytest-capturelog-0.7.tar.gz";
      sha256= "b6e8d5189b39462109c2188e6b512d6cc7e66d62bb5be65389ed50e96d22000d";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [
      self."py"
    ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = licenses.mit;
      description = "py.test plugin to capture log messages";
    };
    passthru.top_level = false;
  };



  "pytest-codecheckers" = python.mkDerivation {
    name = "pytest-codecheckers-0.2";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/53/09/263669db13955496e77017f389693c1e1dd77d98fd4afd51b133162e858f/pytest-codecheckers-0.2.tar.gz";
      sha256= "853de10f204865140da2bc173f791c9e13794fc43656e02fffcce23c9999e748";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [
      self."pep8"
      self."py"
      self."pyflakes"
    ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = "";
      description = "pytest plugin to add source code sanity checks (pep8 and friends)";
    };
    passthru.top_level = false;
  };



  "pytest-cov" = python.mkDerivation {
    name = "pytest-cov-2.3.0";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/6b/58/14b1ddcfd926199ff1468496bc0268bd37f81d949dcad414ce662538c72d/pytest-cov-2.3.0.tar.gz";
      sha256= "b079fa99d4dd4820ac31fe1863df4053eaff787f65dd04024bd57c2666c35ad4";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [
      self."coverage"
      self."pytest"
    ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = licenses.mit;
      description = "Pytest plugin for measuring coverage.";
    };
    passthru.top_level = false;
  };



  "pytest-runner" = python.mkDerivation {
    name = "pytest-runner-2.9";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/11/d4/c335ddf94463e451109e3494e909765c3e5205787b772e3b25ee8601b86a/pytest-runner-2.9.tar.gz";
      sha256= "50378de59b02f51f64796d3904dfe71b9dc6f06d88fc6bfbd5c8e8366ae1d131";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [ ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = "";
      description = "Invoke py.test as distutils command with dependency resolution";
    };
    passthru.top_level = false;
  };



  "pytest-timeout" = python.mkDerivation {
    name = "pytest-timeout-1.0.0";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/cf/92/ab29b9baa54d47dfd50e43be35577de9af4e7ebf27d29f546ddeb6c3b6f5/pytest-timeout-1.0.0.tar.gz";
      sha256= "1465096be73e16df1e15d1b1453692428a7e15b997d756bc565aee0d12798ce1";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [
      self."pytest"
    ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = licenses.mit;
      description = "py.test plugin to abort hanging tests";
    };
    passthru.top_level = false;
  };



  "requests" = python.mkDerivation {
    name = "requests-2.10.0";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/49/6f/183063f01aae1e025cf0130772b55848750a2f3a89bfa11b385b35d7329d/requests-2.10.0.tar.gz";
      sha256= "63f1815788157130cee16a933b2ee184038e975f0017306d723ac326b5525b54";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [ ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = licenses.asl20;
      description = "Python HTTP for Humans.";
    };
    passthru.top_level = false;
  };



  "setuptools-scm" = python.mkDerivation {
    name = "setuptools-scm-1.11.1";
    src = pkgs.fetchurl {
      url = "https://pypi.python.org/packages/84/aa/c693b5d41da513fed3f0ee27f1bf02a303caa75bbdfa5c8cc233a1d778c4/setuptools_scm-1.11.1.tar.gz";
      sha256= "8c45f738a23410c5276b0ed9294af607f491e4260589f1eb90df8312e23819bf";
    };
    doCheck = commonDoCheck;
    buildInputs = commonBuildInputs;
    propagatedBuildInputs = [ ];
    meta = with pkgs.stdenv.lib; {
      homepage = "";
      license = licenses.mit;
      description = "the blessed package to manage your versions by scm tags";
    };
    passthru.top_level = false;
  };

}