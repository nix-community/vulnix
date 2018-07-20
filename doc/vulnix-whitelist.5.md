# vulnix-whitelist - Whitelist file format

## DESCRIPTION

Whitelists exclude matching program versions from the list of vulnerabilities
reported by vulnix(1). Each whitelist file consists of a list of **rules**. Each
rule defines matching criteria. If a derivation in question is not matched by
any whitelist rule, it gets reported.

* program:
  The part of a derivation name before the first dash followed by a digit.

* version:
  The part of a derivation name starting at the first digit after a dash.

* cve:
  One or more reported CVE identifiers.

Additionally, whitelist rules can contain an expiry date (**until**), and both a
free-text comment and an URL to an issue tracker for informational purposes.

### TOML format

Each rule is started by a TOML section header. The following forms are allowed:

* `["`<PROGRAM>`-`<VERSION>`"]`:
  Matches derivations with the specified program name and version.

* `["`<PROGRAM>`"]`:
  Matches derivations with the specified program name and an arbitrary version
  for which no more specific rule is present.

* `["*"]`:
  Matches arbitrary derivations that are not covered by a more specific rule.
  Note that the `cve` field must be specified in this case.

Each rule is optionally followed by the following fields:

* `cve = ["`<CVEID>`",` _..._`]`:
  This rule is only valid if the reported CVE advisories are a subset of those
  specified here. In case additional CVEs are found, this rule becomes invalid.

* `until = "`<YYYY-MM-DD>`"`:
  Matching derivations are reported only from the specified date on.

* `comment = "`<TEXT>`"`:
  Contains notes to fellow users, e.g. to explain why a whitelist rule has been
  written. A list of strings is also allowed.

* `issue_url = "`<URL>`"`:
  A link to a ticket in some issue tracker where the development of fixes gets
  tracked. A list of URLs is also allowed.


### YAML format (deprecated)

Whitelist may also be specified in the legacy YAML format. A whitelist file
consists of a list of dicts with the keys `name` (derivation name), `version`,
`cve` (list of CVE identifiers), `comment` (free text), `status` (ignored; for
compatibility reasons). Note that the `issue_url` field is not valid in YAML
whitelists.

## NOTES

For any given derivation, all relevant rules are applied in order of decreasing
specificity.

Multiple whitelists can be used by passing more than one `-w` option to
`vulnix`. Multiple whitelist are merged in order. For merging, the following
rules apply:

* Rules containing a version and those without are considered different. Only
  rules with the same headers are merged.

* CVE lists are concatenated and duplicates are removed.

* Comments and issue URLs are converted to lists and concatenated.

## EXAMPLES

Whitelist in TOML format with three rules:
The first one matches a specific version of `PCRE` until a given date.
The second one matches all versions of GNU `patch` as long as the set of
published CVEs is a subset of the listed CVEs. The third matches any
derivation which is affected by no more than the listed CVEs.

```
["pcre-8.41"]
until = "2018-03-01"
comment = "should be fixed in a month"
issue_url = "https://tracker.example.com/12345"

["patch"]
cve = ["CVE-2018-6952", "CVE-2018-6951"]
comment = "won't fix these two, but alert me if there is a new CVE"

["*"]
cve = [
  "CVE-2017-6827",
  "CVE-2017-6834",
  "CVE-2017-6828",
  "CVE-2017-6833",
]
```

## SEE ALSO

vulnix(1), [Nix manual](https://nixos.org/nix/manual/),
[TOML](https://github.com/toml-lang/toml), [YAML](http://yaml.org)
