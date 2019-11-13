# vulnix - Nix(OS) vulnerability scanner

## SYNOPSIS

`vulnix` [`OPTIONS`] _--system_

`vulnix` [`OPTIONS`] _PATH_ _..._

## DESCRIPTION

`vulnix` searches Nix derivations together with its transitive closure for
vulnerable software versions as published in the NIST NVD. Affected
derivations are reported together with matching CVE identifiers.

The last argument specifies where to start the search and can be either:

* A derivation file (e.g., _/nix/store/0123456789-program-1.0.drv_).
* A file in the Nix store for which a deriver is known.
* A link into the Nix store (e.g. _result_).

Prior to scanning, parts of the NIST NVD database are fetched and parsed.  This
database copy is cached between `vulnix` invocations and checked in regular
intervals.

`vulnix` uses whitelists to mask certain combinations of packages and CVEs that
should not be reported.

## OPTIONS

* `-S`, `--system`:
  Scans the current system defined as transitive closure of
  _/run/current-system_.

* `-G`, `--gc-roots`:
  Scans all active garbage collection roots. This option is of limited use since
  the scan will include all old system generations.

* `-w`, `--whitelist`=<FILE> | <URL>:
  Loads a whitelist from the specified local path or URL. See
  vulnix-whitelist(5) for an explanation of the whitelist syntax. It is not an
  error if the path/URL does not exist. This option can be given multiple times.

* `-W`, `--write-whitelist`=<FILE>:
  Writes a new copy of the whitelist which contains all reported vulnerable
  package versions in addition to existing whitelist entries (those loaded
  with `-w`). This option can be used to evolve whitelists so that every
  vulnerable version gets reported only once. Note that expired whitelist
  entries (e.g., those where the date set with the `until` option has passed)
  will not be written into the new whitelist.

* `-r`, `--requisites` / `-R`, `--no-requisites`:
  Determines if the transitive closure of the specified paths should be
  computed and scanned or only the given pathnames. Defaults to `--requisites`.

* `-c`, `--cache-dir`=<DIRECTORY>:
  Puts cached NVD entries into <DIRECTORY>. The directory will be created if it
  does not exist. Defaults to _~/.cache/vulnix_.

* `-m`, `--mirror`=<URL>:
  Fetches NIST NVD updates from <URL>. Defaults to
  _https://static.nvd.nist.gov/feeds/xml/cve/_.

* `-j`, `--json`:
  Outputs affected package versions as JSON document. See [JSON output] below.

* `-s`, `--show-whitelisted`:
  Shows whitelisted results in addition to regular (non-whitelisted)
  results.

* `-v`, `--verbose`:
  Prints additional pieces of information on _stderr_. This includes NVD
  updates, derivation paths and clickable links to CVE advisories. May be given
  twice for an extra level of debugging information.

* `-V`, `--version`:
  Prints program version and exits.

* `--help`:
  Prints options summary and exits.


## EXIT STATUS

Exit status are compatible with the [Nagios plugin development
guidelines](https://nagios-plugins.org/doc/guidelines.html) which means that it
can be directly used in the majority of monitoring systems.

`vulnix` exits 0 if no vulnerabilities are found. If all of the
shown vulnerabilities are whitelisted, it exits 1. Otherwise, found
vulnerabilities lead to exit status 2. Exit status 3 indicates an error
condition.

Note that exit status 1 may never occur if the `--show-whitelisted` option is
not given.


## ENVIRONMENT

The following environment variables affect `vulnix`:

* HOME:
  Determines the default cache directory.

* PATH:
  Used to invoke up low-level Nix utilities like `nix-store`.


## FILES ##

`vulnix` maintains a cache dir located at _~/.cache/vulnix_ by default.

The Nix store is assumed to be under _/nix/store_. This pathname is hardcoded.


## NOTES

### Patch detection

`vulnix` tries to detect patches for specific CVEs. These are automatically
excluded from reports.

The `patches` field of each derivation is scanned for names containing CVE
identifiers. If a single patch fixes multiple vulnerabilities, all relevant CVE
identifiers should be given in the patch name, separated by arbitrary
non-numerical characters. See [EXAMPLES] below.

### JSON output

When invoked with `--json`, a JSON document consisting of a list of dicts is
written to stdout. Each list item is an affected derivation and contains the
following keys:

- _name_ - package name and version
- _pname_ - package name without version
- _version_ - version only
- _affected_by_ - list of applicable CVE identifiers
- _whitelisted_ - list of CVE identifiers which are masked by whitelist entries
- _derivation_ - pathname of the scanned derivation file
- _cvssv3_basescore_ - dict of CVSS v3 impact base scores for each CVE found

## BUGS

Invoking `vulnix` with an empty cache directory can take quite a while since it
needs to download and process NIST NVD archives of the last 5 years. Once
initialized, only changed entries are fetched.

The cache directory grows slowly but steadily as there new CVE advisories added
on an ongoing basis.

## COMPATIBILITY

`vulnix` is known to parse derivation files created by `Nix` versions up
to 2.3.


## EXAMPLES

Is my NixOS system vulnerable?

```
vulnix --system
```

Scan the output of nix-build(1) for dependencies with security advisories:

```
nix-build ... -o result
vulnix result
```

Report advisories for a derivation and its transitive closure as structured
JSON document:

```
vulnix -j /nix/store/cm0lrdrf6crb5v38iyygfsbzvivpmh6w-python3-3.6.4.drv
```

Report all advisories affecting the NixOS base install with whitelisting of
formerly known vulnerabilities and creation of an updated whitelist (a.k.a.
vulnerability roundup):

```
nix-build -I nixpkgs=. nixos/release-combined.nix
vulnix -j \
  -w https://raw.githubusercontent.com/ckauhaus/nixos-vulnerability-roundup/master/whitelists/master.toml \
  -W whitelist-master-new.toml \
  result
```

An excerpt from a derivation source which applies a patch against CVE-2018-9055.
Note the **name** attribute which contains an CVE identifier:

```
patches = [
  (fetchpatch {
    name = "CVE-2018-9055.patch";
    url = http://paste.opensuse.org/view/raw/330751ce;
    sha256 = "0m798m6c4v9yyhql7x684j5kppcm6884n1rrb9ljz8p9aqq2jqnm";
  })
];
```

If the patch fixes two vulnerabilities, it could be named
_CVE-2018-9055+CVE-2018-9600.patch_, for example.


## SEE ALSO

vulnix-whitelist(5), nix-store(1), nix-build(1),
[NIST NVD](https://nvd.nist.gov),
[Nix](https://nixos.org/nix/)
