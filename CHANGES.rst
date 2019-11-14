Changes
=======


1.9.1 (2019-11-14)
------------------

- Fix packaging bug.


1.9.0 (2019-11-13)
------------------

- Pull NVD feeds from https://nvd.nist.gov/feeds/json/cve/1.1/ as XML feeds have
  been discontinued (#55).

- Print CVSS v3 base scores for each CVE. Order by descending CVSS score (#53).

- Evaluate version ranges in CPE entries.


1.8.2 (2019-06-17)
------------------

- Process package versions containing a hyphen properly (e.g., R versions)
  (#50).


1.8.1 (2019-04-08)
------------------

- Builds with both PyYAML 3.13 and 5.1 (#49).


1.8.0 (2019-03-09)
------------------

- Exit code 1 is returned only in conjunction with `--show-whitelisted` (#45).
- Fix bug in the processing of the 'until' whitelist field (#43).


1.7.1 (2018-07-23)
------------------

- Improve error messages when TOML files contain syntax errors.
- Fix install requirements so that they match upstream nixpkgs
  (NixOS/nixpkgs#43999).


1.7 (2018-07-20)
----------------

- Selective CVE reporting: Only those CVEs are reported for which no whitelist
  entry exists (#41).
- Consider all applicable whitelist entries for a given package (pkg-version,
  pkg, "*") (#42).
- Refine TOML section header check.


1.6.3 (2018-05-02)
------------------

- *Really* fix FC-101294. Now for whitelists containing more than one line :)
- Fail on spaces between package and version in whitelist headers.


1.6.2 (2018-05-02)
------------------

- Sort CVEs in JSON output.
- Bugfix: fail clearly if section headers are not quoted (FC-101294).


1.6.1 (2018-04-20)
------------------

- Parse derivation files with `__structuredAttrs = true` (#37).


1.6.0 (2018-04-19)
------------------

- Completely reworked whitelisting subsystem. Whitelists can now be written as
  TOML files and support a more expressive range of options including expiry
  datedates. The old YAML syntax is still supported (#36).
- Ignore case when guessing CVE identifiers from patch file names (thanks to
  @adisbladis).
- Add man pages (#29).


1.4.0 (2017-11-27)
------------------

- Guesses applied CVE patches out of the `patches` derivation envVar (see
  nixpkgs FC-15660).


1.3.4 (2017-10-29)
------------------

- Add '--no-requisites' flag which stops vulnix from determining the transitive
  closure of derivations passed on the command line.
- Provide structured JSON output with `--json`.
- Remove whitelist from README as it is quite buggy right now.


1.3.3 (2017-10-16)
------------------

- Fix return code bug (FC-28741).
- Fix partial whitelisting of products where several vulnerable versions are
  present on the system at the same time (#24).
- Improve error reporting for incorrectly formed whitelist rules.


1.3.2 (2017-10-06)
------------------

- Minor: fix packaging issues.


1.3.1 (2017-10-06)
------------------

- Security: Fix arbitrary code execution bug during derivation evaluation.


1.3.0 (2017-09-18)
------------------

- `.drv` files may be specified directly on the command line.
- Updated PyPI dependencies.
- Document system requirements (#12).
- Don't leave large files in /tmp around.
- Remove duplicate CVEs in output (#25).
- Fix bug with reporting less than 3 vulnerabilities (#28).


1.2.2 (2017-01-28)
------------------

- Packaging improvements: pin versions in setup.py, include NVDCVE test data in
  sdist.
- Reduce NVDCVE fixture size. This cuts tests run time by more than 50%.


1.2.1 (2017-01-27)
------------------

- Skip `/nix/var/nix/gcroots/booted-system` during system check.
- Make output a bit easier to read by removing visual clutter.


1.2 (2016-12-22)
----------------

- Improve CPU and memory usage: refactored the way we fetch, parse, store and
  process data. We now leverage ZODB as the storage for parsed data that is
  efficient to look up.

  On our test systems this caused memory usage to drop from > 1GiB to ~70MiB
  and a pure evaluation of existing data to around 7-10 seconds.

  This change requires a re-retrieval of all historic sources.

- Improve unit test coverage with at least a smoke test for our new fetching
  procedure.

1.1.5 (2016-10-13)
------------------

- Keep a reverse index: product name -> vulnerabilities to speed up scan process.
- Mark 'in progress' vulnerabilities with an asterisk
- The '-w' switch accepts URLs, too
- vulnix no longer scans /var/nix/var/gcroots/booted-system
- only cached files are saved (archives are to be deleted)
- added travis build: runs periodically against nixpkgs/master and updates
  requirements*.nix files in case of success


1.1.4 (2016-08-25)
------------------

- Add `src` to PYTHONPATH so that tests run also on older NixOS versions
  (tested on 15.09).
- Correct URL, add metadata.
- Add nix to propagatedBuildInputs, as vulnix calls `nix-store` at runtime.


1.1.3 (2016-08-16)
------------------

- Pin the Python version to 3.4 (Nix only)


1.1.2 (2016-08-15)
------------------

- Add Nix expressions (Nix/NixOS) to MANIFEST.in


1.1.1 (2016-08-12)
------------------

- Add VERSION to MANIFEST.in


1.1 (2016-08-11)
----------------

- Scans the whole system (NixOS only), the current user environment, or a
  project-specific path (e.g., ./result). #1

- Allow to specify site-specific whitelists in addition to the builtin default
  whitelist. #4

- Fully repeatable install using default.nix. Thanks to Rok Garbas. #4

- Cache pre-parsed NVD files for improved scanning speed. #2

- Support multiple whitelists (repeat -w option). #3

- Cache NVD files in `~/.cache/vulnix`. #7

- Document whitelist file format. #10

- Fix Nix build on macOS. #11
