Nix(OS) vulnerability scanner
=============================

.. image:: https://travis-ci.org/flyingcircusio/vulnix.svg?branch=master
    :target: https://travis-ci.org/flyingcircusio/vulnix

This is a utility that validates a Nix store for any packages that are
reachable from live paths and likely to be affected by vulnerabilities
listed in the NVD.

It implements a CLI utility to inspect the current status and a
monitoring integration for Sensu.

Example output:

::

    Security issues for sqlite, libxml2, ... (and 10 more)

    sqlite-2.9.3 (inprogress)
        https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-2073
        https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-8710

        See https://plan.flyingcircus.io/issues/18544


    libxml2-2.9.3
        https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-3717

Usage:

::

    $ nix-build
    $ ./result/bin/vulnix

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

Every rule starts with the ``-`` and a new-line, declaring a list
element.

+--------------+--------------------+--------------------+
| Element      | Example value      | Description        |
+==============+====================+====================+
| cve          | cve: CVE-2015-2503 | Ignores all        |
|              |                    | matches which are  |
|              |                    | referred by the    |
|              |                    | CVE                |
+--------------+--------------------+--------------------+
| comment      | comment: microsoft | comments the rule  |
|              | access, accidently |                    |
|              | matching the       |                    |
|              | 'access'           |                    |
|              | derivation         |                    |
+--------------+--------------------+--------------------+
| name         | name: libxslt      | refers to the name |
|              |                    | attribute of a     |
|              |                    | package derivation |
+--------------+--------------------+--------------------+
| status       | status: inprogress | Marks the found    |
|              |                    | vulnerabilty as    |
|              |                    | being worked on.   |
|              |                    | "\*" will be added |
|              |                    | to the derivation  |
+--------------+--------------------+--------------------+
| version      | version: 2.0       | refers to the name |
|              |                    | attribute of a     |
|              |                    | package derivation |
+--------------+--------------------+--------------------+
| vendor       | microsoft          | refers to the      |
|              |                    | [NIST]             |
|              |                    | (https://nvd       |
|              |                    | .nist.gov/cp       |
|              |                    | e.cfm) term of the |
|              |                    | person or          |
|              |                    | organization which |
|              |                    | created the        |
|              |                    | software           |
+--------------+--------------------+--------------------+
| product      | access             | Like vendor it's a |
|              |                    | term coined by     |
|              |                    | NIST and is an     |
|              |                    | analogy to what    |
|              |                    | name means for Nix |
+--------------+--------------------+--------------------+

Example
-------

There is an `example <src/vulnix/default_whitelist.yaml>`__ for a
working whitelist file as part of the unit tests.
