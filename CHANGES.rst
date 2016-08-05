0.1 (unreleased)
================

- Scans the whole system (NixOS only), the current user environment, or a
  project-specific path (e.g., ./result). #1

- Allow to specify site-specific whitelists in addition to the builtin default
  whitelist. #4

- Fully repeatale install using default.nix. Thanks to Rok Garbas. #4

- Cache pre-parsed NVD files for improved scanning speed. #2
