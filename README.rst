Nix(OS) vulnerability scanner
=============================

This is a utility that validates a Nix store for any packages that are
reachable from live paths and likely to be affected by vulnerabilities
listed in the NVD.

It implements a CLI utility to inspect the current status and a
monitoring integration for Sensu.

Example output::

  Found 5 advisories for libxslt, pcre, perl, ... (and 2 more)

  ========================================================================
  libxslt-1.1.29

  CVEs:
          https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-5029

  ========================================================================
  pcre-8.40

  CVEs:
          https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-7245
          https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-7244
          [...]


Theory of operation
-------------------

`vulnix` pulls all published CVEs from NIST and caches them locally. It
matches name and version of all derivations referenced from the command line
against known CVE entries. A *whitelist* is used to filter out unwanted results.


System requirements
-------------------

- Depends on common Nix tools like `nix-store`. These are expected to be in
  $PATH.
- Depends on being able to interact with the Nix store database
  (/nix/var/nix/db). This means that it must either run as the same user that
  owns the Nix store database or `nix-daemon` must be active.
- It refuses to work without some locale environment settings. Try `export
  LANG=C.UTF-8` if you see encoding errors.

Usage Example
=============

- What vulnerabilities are listed for my current system::

    vulnix --system

- Check `nix-build` output together with its transitive closure::

    vulnix result/

- Check all passed derivations, but don't determine requisites::

    vulnix -R /nix/store/*.drv

- JSON output for machine post-processing::

    vulnix --json result/


Whitelist
=========

The whitelist file uses a sub-set of the
`YAML <https://en.wikipedia.org/wiki/YAML>`__ language to define rules
which matches shall be ignored or in other words are declared to be
trusted or in progress, hence the term whitelist. If the match is
**partial**, e.G. there is a package which is affected by more than one
vulnerability, but only one is whitelist, the match will still be
printed except for the declared exception.

Syntax
------

[TBD: the whitelist feature is being revamped at the moment]
