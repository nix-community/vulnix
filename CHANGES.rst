Changes
=======

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
