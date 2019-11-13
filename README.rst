Nix(OS) vulnerability scanner
=============================

This is a utility that validates a Nix store for any packages that are
reachable from live paths and likely to be affected by vulnerabilities
listed in the NVD.

It implements a CLI utility to inspect the current status and a
monitoring integration for Sensu.

Example output::

  2 derivations with active advisories

  ------------------------------------------------------------------------
  libxslt-1.1.29

  CVE-2017-5029

  ------------------------------------------------------------------------
  pcre-8.40

  CVE-2017-7245
  CVE-2017-7244
  [...]


Theory of operation
-------------------

`vulnix` pulls all published CVEs from NIST_ and caches them locally. It
matches name and version of all derivations referenced from the command line
against known CVE entries. A *whitelist* is used to filter out unwanted results.

Matching Nix package names to NVD products is currently done via a coarse
heuristic. First, a direct match is tried. If no product can be found,
variations with lower case and underscore instead of hyphen are tried. It is
clear that this mapping is too simplistic and needs to be improved in future
versions.


System requirements
-------------------

- Depends on common Nix tools like `nix-store`. These are expected to be in
  $PATH.
- Depends on being able to interact with the Nix store database
  (/nix/var/nix/db). This means that it must either run as the same user that
  owns the Nix store database or `nix-daemon` must be active.
- Parses `*.drv` files directly. Tested with Nix >=1.10 and 2.x.
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

Section headings - package selection
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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

cve
  List of CVE identifiers to match. The whitelist rule is valid as long as the
  detected CVEs are a subset of the CVEs listed here. If additional CVEs are
  detected, this whitelist rule is not effective anymore.

until
  Date in the form "YYYY-MM-DD" which confines this rule's lifetime. On the
  specified date and later, this whitelist rule is not effective anymore.

issue_url
  URL or list of URLs that point to any issue tracker. Informational only.

comment
  String or list of strings containing free text. Informational only.


Examples
--------

Create a ticket on your favourite issue tracker. Estimate the time to get the
vulnerable package fixed. Create whitelist entry::

  ["ffmpeg-3.4.2"]
  cve = ["CVE-2018-6912", "CVE-2018-7557"]
  until = "2018-05-01"
  issue_url = "https://issues.example.com/29952"
  comment = "need to backport patch"

This particular version of ffmpeg will be left out from reports until either
another CVE gets published or the specified date is reached.


CVE patch auto-detection
========================

`vulnix` will inspect derivations for patches which supposedly fix specific
CVEs. When a patch filename contains one or more CVE identifiers, these will not
reported anymore. Example Nix code::

  patches = [ ./CVE-2018-6951.patch ];

Patches which fix multiple CVEs should name them all with a non-numeric
separator, e.g. `CVE-2017-14159+CVE-2017-17740.patch`.

Auto-detection even works when patches are pulled via `fetchpatch` and friends
as long as there is a CVE identifier in the name. Example::

  patches = [
    (fetchpatch {
      name = "CVE-2018-9055.patch";
      url = http://paste.opensuse.org/view/raw/330751ce;
      sha256 = "0m798m6c4v9yyhql7x684j5kppcm6884n1rrb9ljz8p9aqq2jqnm";
    })
  ];


.. _NIST: https://nvd.nist.gov/vuln/
.. _TOML: https://github.com/toml-lang/toml/
