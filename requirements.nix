# generated using pypi2nix tool (version: 1.8.0)
# See more at: https://github.com/garbas/pypi2nix
#
# COMMAND:
#   pypi2nix -V 3.5 -E libxml2 -E libxslt -r requirements.txt
#

{ pkgs ? import <nixpkgs> {}
}:

let

  inherit (pkgs) makeWrapper;
  inherit (pkgs.stdenv.lib) fix' extends inNixShell;

  pythonPackages =
  import "${toString pkgs.path}/pkgs/top-level/python-packages.nix" {
    inherit pkgs;
    inherit (pkgs) stdenv;
    python = pkgs.python35;
    # patching pip so it does not try to remove files when running nix-shell
    overrides =
      self: super: {
        bootstrapped-pip = super.bootstrapped-pip.overrideDerivation (old: {
          patchPhase = old.patchPhase + ''
            sed -i               -e "s|paths_to_remove.remove(auto_confirm)|#paths_to_remove.remove(auto_confirm)|"                -e "s|self.uninstalled = paths_to_remove|#self.uninstalled = paths_to_remove|"                  $out/${pkgs.python35.sitePackages}/pip/req/req_install.py
          '';
        });
      };
  };

  commonBuildInputs = with pkgs; [ libxml2 libxslt ];
  commonDoCheck = false;

  withPackages = pkgs':
    let
      pkgs = builtins.removeAttrs pkgs' ["__unfix__"];
      interpreter = pythonPackages.buildPythonPackage {
        name = "python35-interpreter";
        buildInputs = [ makeWrapper ] ++ (builtins.attrValues pkgs);
        buildCommand = ''
          mkdir -p $out/bin
          ln -s ${pythonPackages.python.interpreter}               $out/bin/${pythonPackages.python.executable}
          for dep in ${builtins.concatStringsSep " "               (builtins.attrValues pkgs)}; do
            if [ -d "$dep/bin" ]; then
              for prog in "$dep/bin/"*; do
                if [ -f $prog ]; then
                  ln -s $prog $out/bin/`basename $prog`
                fi
              done
            fi
          done
          for prog in "$out/bin/"*; do
            wrapProgram "$prog" --prefix PYTHONPATH : "$PYTHONPATH"
          done
          pushd $out/bin
          ln -s ${pythonPackages.python.executable} python
          ln -s ${pythonPackages.python.executable}               python3
          popd
        '';
        passthru.interpreter = pythonPackages.python;
      };
    in {
      __old = pythonPackages;
      inherit interpreter;
      mkDerivation = pythonPackages.buildPythonPackage;
      packages = pkgs;
      overrideDerivation = drv: f:
        pythonPackages.buildPythonPackage (drv.drvAttrs // f drv.drvAttrs //                                            { meta = drv.meta; });
      withPackages = pkgs'':
        withPackages (pkgs // pkgs'');
    };

  python = withPackages {};

  generated = self: {

    "BTrees" = python.mkDerivation {
      name = "BTrees-4.4.1";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/6a/e2/d8c2a5b4cbc493b1ccb440d61bf0f62b8a0cb1c7b5aa403d5e18847545b3/BTrees-4.4.1.tar.gz"; sha256 = "a2738b71693971c1f7502888d649bef270c65f026db731e03d53f1ec4edfe8a3"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [
      # break circular dependency
      # see https://github.com/garbas/pypi2nix/issues/150
      # self."ZODB"
      self."coverage"
      self."persistent"
      self."transaction"
      self."zope.interface"
    ];
      meta = with pkgs.stdenv.lib; {
        homepage = "http://packages.python.org/BTrees";
        license = licenses.zpt21;
        description = "Scalable persistent object containers";
      };
    };



    "PyYAML" = python.mkDerivation {
      name = "PyYAML-3.12";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/4a/85/db5a2df477072b2902b0eb892feb37d88ac635d36245a72a6a69b23b383a/PyYAML-3.12.tar.gz"; sha256 = "592766c6303207a20efc445587778322d7f73b161bd994f227adaa341ba212ab"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [ ];
      meta = with pkgs.stdenv.lib; {
        homepage = "http://pyyaml.org/wiki/PyYAML";
        license = licenses.mit;
        description = "YAML parser and emitter for Python";
      };
    };



    "ZConfig" = python.mkDerivation {
      name = "ZConfig-3.2.0";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/d4/92/fc40144b727ee0fc01ee51a52b0c95ddd48179a1137cf785031d6e7e33d8/ZConfig-3.2.0.tar.gz"; sha256 = "de0a802e5dfea3c0b3497ccdbe33a5023c4265f950f33e35dd4cf078d2a81b19"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [ ];
      meta = with pkgs.stdenv.lib; {
        homepage = "https://github.com/zopefoundation/ZConfig/";
        license = licenses.zpt21;
        description = "Structured Configuration Library";
      };
    };



    "ZODB" = python.mkDerivation {
      name = "ZODB-5.2.4";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/15/5a/1ffa400b7ca7b1df5dc0de2bd25e1d4946c258c797216b2aef6f0bf946b0/ZODB-5.2.4.tar.gz"; sha256 = "ecc1c9c1ef494a70ccfc03184bccb72421d72233e9dc4742ac58f5396d04cadf"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [
      self."BTrees"
      self."ZConfig"
      self."persistent"
      self."six"
      self."transaction"
      self."zc.lockfile"
      self."zodbpickle"
      self."zope.interface"
    ];
      meta = with pkgs.stdenv.lib; {
        homepage = "http://www.zodb.org/";
        license = licenses.zpt21;
        description = "ZODB, a Python object-oriented database";
      };
    };



    "certifi" = python.mkDerivation {
      name = "certifi-2017.7.27.1";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/20/d0/3f7a84b0c5b89e94abbd073a5f00c7176089f526edb056686751d5064cbd/certifi-2017.7.27.1.tar.gz"; sha256 = "40523d2efb60523e113b44602298f0960e900388cf3bb6043f645cf57ea9e3f5"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [ ];
      meta = with pkgs.stdenv.lib; {
        homepage = "http://certifi.io/";
        license = "MPL-2.0";
        description = "Python package for providing Mozilla's CA Bundle.";
      };
    };



    "chardet" = python.mkDerivation {
      name = "chardet-3.0.4";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/fc/bb/a5768c230f9ddb03acc9ef3f0d4a3cf93462473795d18e9535498c8f929d/chardet-3.0.4.tar.gz"; sha256 = "84ab92ed1c4d4f16916e05906b6b75a6c0fb5db821cc65e70cbd64a3e2a5eaae"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [ ];
      meta = with pkgs.stdenv.lib; {
        homepage = "https://github.com/chardet/chardet";
        license = licenses.lgpl2;
        description = "Universal encoding detector for Python 2 and 3";
      };
    };



    "click" = python.mkDerivation {
      name = "click-6.7";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/95/d9/c3336b6b5711c3ab9d1d3a80f1a3e2afeb9d8c02a7166462f6cc96570897/click-6.7.tar.gz"; sha256 = "f15516df478d5a56180fbf80e68f206010e6d160fc39fa508b65e035fd75130b"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [ ];
      meta = with pkgs.stdenv.lib; {
        homepage = "http://github.com/mitsuhiko/click";
        license = licenses.bsdOriginal;
        description = "A simple wrapper around optparse for powerful command line utilities.";
      };
    };



    "colorama" = python.mkDerivation {
      name = "colorama-0.3.9";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/e6/76/257b53926889e2835355d74fec73d82662100135293e17d382e2b74d1669/colorama-0.3.9.tar.gz"; sha256 = "48eb22f4f8461b1df5734a074b57042430fb06e1d61bd1e11b078c0fe6d7a1f1"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [ ];
      meta = with pkgs.stdenv.lib; {
        homepage = "https://github.com/tartley/colorama";
        license = licenses.bsdOriginal;
        description = "Cross-platform colored terminal text.";
      };
    };



    "coverage" = python.mkDerivation {
      name = "coverage-4.4.1";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/36/db/690ee79312bb60f121c0da1c973856ddb751afe09cc10caec1452208eaf4/coverage-4.4.1.tar.gz"; sha256 = "7a9c44400ee0f3b4546066e0710e1250fd75831adc02ab99dda176ad8726f424"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [ ];
      meta = with pkgs.stdenv.lib; {
        homepage = "https://coverage.readthedocs.io";
        license = licenses.asl20;
        description = "Code coverage measurement for Python";
      };
    };



    "idna" = python.mkDerivation {
      name = "idna-2.5";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/d8/82/28a51052215014efc07feac7330ed758702fc0581347098a81699b5281cb/idna-2.5.tar.gz"; sha256 = "3cb5ce08046c4e3a560fc02f138d0ac63e00f8ce5901a56b32ec8b7994082aab"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [ ];
      meta = with pkgs.stdenv.lib; {
        homepage = "https://github.com/kjd/idna";
        license = licenses.bsdOriginal;
        description = "Internationalized Domain Names in Applications (IDNA)";
      };
    };



    "lxml" = python.mkDerivation {
      name = "lxml-3.8.0";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/20/b3/9f245de14b7696e2d2a386c0b09032a2ff6625270761d6543827e667d8de/lxml-3.8.0.tar.gz"; sha256 = "736f72be15caad8116891eb6aa4a078b590d231fdc63818c40c21624ac71db96"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [ ];
      meta = with pkgs.stdenv.lib; {
        homepage = "http://lxml.de/";
        license = licenses.bsdOriginal;
        description = "Powerful and Pythonic XML processing library combining libxml2/libxslt with the ElementTree API.";
      };
    };



    "persistent" = python.mkDerivation {
      name = "persistent-4.2.4.2";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/c8/a7/42e650ec8a789fde5b8c734d65eb237a1a361d5c82d22f0c22e98e897cca/persistent-4.2.4.2.tar.gz"; sha256 = "cf264cd55866c7ffbcbe1328f8d8b28fd042a5dd0c03a03f68c0887df3aa1964"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [
      self."coverage"
      self."zope.interface"
    ];
      meta = with pkgs.stdenv.lib; {
        homepage = "http://www.zope.org/Products/ZODB";
        license = licenses.zpt21;
        description = "Translucent persistent objects";
      };
    };



    "py" = python.mkDerivation {
      name = "py-1.4.34";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/68/35/58572278f1c097b403879c1e9369069633d1cbad5239b9057944bb764782/py-1.4.34.tar.gz"; sha256 = "0f2d585d22050e90c7d293b6451c83db097df77871974d90efd5a30dc12fcde3"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [ ];
      meta = with pkgs.stdenv.lib; {
        homepage = "http://py.readthedocs.io/";
        license = licenses.mit;
        description = "library with cross-python path, ini-parsing, io, code, log facilities";
      };
    };



    "pytest" = python.mkDerivation {
      name = "pytest-3.2.1";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/6d/9f/1fbd50be4deaa4007ef4ed8f84f888c6613c629e1f46e979ffb9d82a7324/pytest-3.2.1.tar.gz"; sha256 = "4c2159d2be2b4e13fa293e7a72bdf2f06848a017150d5c6d35112ce51cfd74ce"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [
      self."colorama"
      self."py"
    ];
      meta = with pkgs.stdenv.lib; {
        homepage = "http://pytest.org";
        license = licenses.mit;
        description = "pytest: simple powerful testing with Python";
      };
    };



    "pytest-catchlog" = python.mkDerivation {
      name = "pytest-catchlog-1.2.2";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/f2/2b/2faccdb1a978fab9dd0bf31cca9f6847fbe9184a0bdcc3011ac41dd44191/pytest-catchlog-1.2.2.zip"; sha256 = "4be15dc5ac1750f83960897f591453040dff044b5966fe24a91c2f7d04ecfcf0"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [
      self."py"
      self."pytest"
    ];
      meta = with pkgs.stdenv.lib; {
        homepage = "https://github.com/eisensheng/pytest-catchlog";
        license = licenses.mit;
        description = "py.test plugin to catch log messages. This is a fork of pytest-capturelog.";
      };
    };



    "pytest-cov" = python.mkDerivation {
      name = "pytest-cov-2.5.1";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/24/b4/7290d65b2f3633db51393bdf8ae66309b37620bc3ec116c5e357e3e37238/pytest-cov-2.5.1.tar.gz"; sha256 = "03aa752cf11db41d281ea1d807d954c4eda35cfa1b21d6971966cc041bbf6e2d"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [
      self."coverage"
      self."pytest"
    ];
      meta = with pkgs.stdenv.lib; {
        homepage = "https://github.com/pytest-dev/pytest-cov";
        license = licenses.bsdOriginal;
        description = "Pytest plugin for measuring coverage.";
      };
    };



    "pytest-runner" = python.mkDerivation {
      name = "pytest-runner-2.11.1";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/9e/4d/08889e5e27a9f5d6096b9ad257f4dea1faabb03c5ded8f665ead448f5d8a/pytest-runner-2.11.1.tar.gz"; sha256 = "983a31eab45e375240e250161a556163bc8d250edaba97960909338c273a89b3"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [ ];
      meta = with pkgs.stdenv.lib; {
        homepage = "https://github.com/pytest-dev/pytest-runner";
        license = licenses.mit;
        description = "Invoke py.test as distutils command with dependency resolution";
      };
    };



    "pytest-timeout" = python.mkDerivation {
      name = "pytest-timeout-1.2.0";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/cc/b7/b2a61365ea6b6d2e8881360ae7ed8dad0327ad2df89f2f0be4a02304deb2/pytest-timeout-1.2.0.tar.gz"; sha256 = "c29e3168f10897728059bd6b8ca20b28733d7fe6b8f6c09bb9d89f6146f27cb8"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [
      self."pytest"
    ];
      meta = with pkgs.stdenv.lib; {
        homepage = "http://bitbucket.org/pytest-dev/pytest-timeout/";
        license = licenses.mit;
        description = "py.test plugin to abort hanging tests";
      };
    };



    "requests" = python.mkDerivation {
      name = "requests-2.18.3";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/c3/38/d95ddb6cc8558930600be088e174a2152261a1e0708a18bf91b5b8c90b22/requests-2.18.3.tar.gz"; sha256 = "fb68a7baef4965c12d9cd67c0f5a46e6e28be3d8c7b6910c758fbcc99880b518"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [
      self."certifi"
      self."chardet"
      self."idna"
      self."urllib3"
    ];
      meta = with pkgs.stdenv.lib; {
        homepage = "http://python-requests.org";
        license = licenses.asl20;
        description = "Python HTTP for Humans.";
      };
    };



    "setuptools-scm" = python.mkDerivation {
      name = "setuptools-scm-1.15.6";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/03/6d/aafdd01edd227ee879b691455bf19895091872af7e48192bea1758c82032/setuptools_scm-1.15.6.tar.gz"; sha256 = "49ab4685589986a42da85706b3311a2f74f1af567d39fee6cb1e088d7a75fb5f"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [ ];
      meta = with pkgs.stdenv.lib; {
        homepage = "https://github.com/pypa/setuptools_scm/";
        license = licenses.mit;
        description = "the blessed package to manage your versions by scm tags";
      };
    };



    "six" = python.mkDerivation {
      name = "six-1.10.0";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/b3/b2/238e2590826bfdd113244a40d9d3eb26918bd798fc187e2360a8367068db/six-1.10.0.tar.gz"; sha256 = "105f8d68616f8248e24bf0e9372ef04d3cc10104f1980f54d57b2ce73a5ad56a"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [ ];
      meta = with pkgs.stdenv.lib; {
        homepage = "http://pypi.python.org/pypi/six/";
        license = licenses.mit;
        description = "Python 2 and 3 compatibility utilities";
      };
    };



    "transaction" = python.mkDerivation {
      name = "transaction-2.1.2";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/27/c5/27f1953db67de21832fd977684e639e41c7738dc449886419bb2aa235094/transaction-2.1.2.tar.gz"; sha256 = "b9bc365e7dba3877e0f6fdee32aa029b8c0c1eb4fe227f524bffd5fc46064bd5"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [
      self."coverage"
      self."zope.interface"
    ];
      meta = with pkgs.stdenv.lib; {
        homepage = "https://github.com/zopefoundation/transaction";
        license = licenses.zpt21;
        description = "Transaction management for Python";
      };
    };



    "urllib3" = python.mkDerivation {
      name = "urllib3-1.22";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/ee/11/7c59620aceedcc1ef65e156cc5ce5a24ef87be4107c2b74458464e437a5d/urllib3-1.22.tar.gz"; sha256 = "cc44da8e1145637334317feebd728bd869a35285b93cbb4cca2577da7e62db4f"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [
      self."certifi"
      self."idna"
    ];
      meta = with pkgs.stdenv.lib; {
        homepage = "https://urllib3.readthedocs.io/";
        license = licenses.mit;
        description = "HTTP library with thread-safe connection pooling, file post, and more.";
      };
    };



    "zc.lockfile" = python.mkDerivation {
      name = "zc.lockfile-1.2.1";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/bd/84/0299bbabbc9d3f84f718ba1039cc068030d3ad723c08f82a64337edf901e/zc.lockfile-1.2.1.tar.gz"; sha256 = "11db91ada7f22fe8aae268d4bfdeae012c4fe655f66bbb315b00822ec00d043e"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [ ];
      meta = with pkgs.stdenv.lib; {
        homepage = "http://www.python.org/pypi/zc.lockfile";
        license = licenses.zpt21;
        description = "Basic inter-process locks";
      };
    };



    "zodbpickle" = python.mkDerivation {
      name = "zodbpickle-0.6.0";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/7a/fc/f6f437a5222b330735eaf8f1e67a6845bd1b600e9a9455e552d3c13c4902/zodbpickle-0.6.0.tar.gz"; sha256 = "ea3248be966159e7791e3db0e35ea992b9235d52e7d39835438686741d196665"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [
      self."coverage"
    ];
      meta = with pkgs.stdenv.lib; {
        homepage = "http://pypi.python.org/pypi/zodbpickle";
        license = licenses.zpt21;
        description = "Fork of Python 3 pickle module.";
      };
    };



    "zope.interface" = python.mkDerivation {
      name = "zope.interface-4.4.2";
      src = pkgs.fetchurl { url = "https://pypi.python.org/packages/c5/88/93373971f893714f0dc15e09696ec4886ee8b4e561ce5ae45612c2c516c4/zope.interface-4.4.2.tar.gz"; sha256 = "4e59e427200201f69ef82956ddf9e527891becf5b7cde8ec3ce39e1d0e262eb0"; };
      doCheck = commonDoCheck;
      buildInputs = commonBuildInputs;
      propagatedBuildInputs = [
      self."coverage"
    ];
      meta = with pkgs.stdenv.lib; {
        homepage = "https://github.com/zopefoundation/zope.interface";
        license = licenses.zpt21;
        description = "Interfaces for Python";
      };
    };

  };
  localOverridesFile = ./requirements_override.nix;
  overrides = import localOverridesFile { inherit pkgs python; };
  commonOverrides = [

  ];
  allOverrides =
    (if (builtins.pathExists localOverridesFile)
     then [overrides] else [] ) ++ commonOverrides;

in python.withPackages
   (fix' (pkgs.lib.fold
            extends
            generated
            allOverrides
         )
   )
