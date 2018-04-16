Nix(OS) vulnerability scanner
=============================

This is a utility that validates a Nix store for any packages that are
reachable from live paths and likely to be affected by vulnerabilities
listed in the NVD.

It implements a CLI utility to inspect the current status and a
monitoring integration for Sensu.

Example output::

  Found 5 advisories

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

`vulnix` pulls all published CVEs from NIST_ and caches them locally. It
matches name and version of all derivations referenced from the command line
against known CVE entries. A *whitelist* is used to filter out unwanted results.


System requirements
-------------------

- Depends on common Nix tools like `nix-store`. These are expected to be in
  $PATH.
- Depends on being able to interact with the Nix store database
  (/nix/var/nix/db). This means that it must either run as the same user that
  owns the Nix store database or `nix-daemon` must be active.
- Parses `*.drv` files directly. Tested with Nix 1.10 and 1.11.
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

    vulnix --json /nix/store/my-derivation.drv

See `vulnix --help` for a list of all options.


Whitelisting
============

`vulnix` output may contain false positives, unfixable packages or stuff which
is known to be addressed. The *whitelist* feature allows to exclude packages
matching certain criteria.

Usage
-----

Load whitelists from either local files or HTTP servers::

  vulnix -w /path/to/whitelist.toml \
         -w https://example.org/published-whitelist.toml

Syntax
------

Whitelists are TOML_ files which contain the package to be filtered as section
headers, followed by further per-package options.

Selecting packages
^^^^^^^^^^^^^^^^^^

Exclude a package at a specific version::

  ["openjpeg-2.3.0"]
  ...

Exclude a package regardless of version (additional CVE filters may apply, see
below)::

  ["openjpeg"]

Exclude all packages (see below for CVE filters, again)::

  ["*"]

Options
^^^^^^^

Package selections can be further narrowed by CVE lists::

  ["openjpeg"]
  cve = ["CVE-2017-17479", "CVE-2017-17480"]

This means that the *openjpeg* package will not be reported as long as it
matches only the two specified CVEs. Once another CVE is listed in the database,
it will be reported.

Whitelist rules may have an expiry date with the `until` option::

  ["libarchive-3.3.2"]
  until = "2018-04-01"

This means that libarchive-3.3.2 will be filtered out before 2018-04-01. On that
date and afterwards, it will be reported again.

The options `issue_url` and `comment` can be used to document further details
why this whitelist entry has been created and so on. The former must contain a
valid URLs while the latter is free form. They are only for informational
purposepurposes and will be displayed with `vulnix --show-whitelisted`.

Workflows
---------

Whitelisting allow you to keep uninteresting stuff out of vulnix reports and
concentrate on what is important.

Excluding unfixable packages
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Add a version-specific whitelist rule for packages which have no applicable fix
or where the impact is negligible. If a package is hit completely in error, add
a version-independend whitelist rule.

Example::

  ["exiv2-0.26"]
  comment = "No upstream fix available"


Marking packages as work in progress
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Create a ticket on your favourite issue tracker and put the URL and optionally
an expiry date into the whitelist::

  ["ffmpeg-3.4.2"]
  cve = ["CVE-2018-6912", "CVE-2018-7557"]
  until = "2018-05-01"
  issue_url = "issues.example.com/29952"

If the package is not fixed on the system by the specified date, it will pop up
again in the report. If a new CVE gets published for this package version, it
will be re-reported even before the specified date.


.. _NIST: https://nvd.nist.gov/vuln/
.. _TOML: https://github.com/toml-lang/toml/
