Nix(OS) vulnerability scanner
=============================

This is a utility that validates a Nix store for any packages that are
reachable from live paths and likely to be affected by vulnerabilities listed
in the NVD.

It implements a CLI utility to inspect the current status and a monitoring
integration for Sensu.


Example output:

    Security issues for sqlite, libxml2, ... (and 10 more)


    sqlite-2.9.3 (inprogress)
        https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-2073
        https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-8710

        See https://plan.flyingcircus.io/issues/18544


    libxml2-2.9.3
        https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-3717


Usage::

    $ nix-build
    $ ./result/bin/vulnix
