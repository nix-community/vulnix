from operator import attrgetter
import click
import functools
import json


def fmt_vuln(v, kev, show_description=False):
    cvssv3 = str(v.cvssv3 or "")
    cvssv3 += '!' if kev.is_known_exploited(v.cve_id) else ''
    cvssv3 += '!' if kev.is_past_due(v.cve_id) else ''

    out = 'https://nvd.nist.gov/vuln/detail/{:17}'.format(v.cve_id)
    out += ' {:<10} '.format(cvssv3)
    if show_description:
        # Show the description in a different color as they can run over the
        # line length, and this makes distinguishing them from the next entry
        # easy.
        out += click.style(v.description or "", fg="cyan")
    return out.rstrip()


def vuln_sort_key(v):
    """Sort by CVSSv3 descending and CVE_ID ascending."""
    return (-v.cvssv3, v)


class Filtered:
    """Derivation with whitelist filtering applied.

    Initially, all CVEs are in the `report` set. When whitelist rules
    are added via `add()`, matching CVEs are moved into the `masked`
    set. Output formatting depends on which of these sets have any
    members.
    """

    until = None

    def __init__(self, derivation, vulnerabilities):
        self.derivation = derivation
        self.rules = []
        self.report = vulnerabilities
        self.masked = set()

    def __repr__(self):
        return '<Filtered({}, {}, {}, {})>'.format(
            self.derivation.pname, self.rules, len(self.report),
            len(self.masked))

    def add(self, wl_rule):
        self.rules.append(wl_rule)
        if wl_rule.until:
            if not self.until or self.until > wl_rule.until:
                self.until = wl_rule.until
        if wl_rule.cve:
            for r in wl_rule.cve:
                mask = set(vuln for vuln in self.report
                           if vuln.cve_id in wl_rule.cve)
                self.report -= mask
                self.masked |= mask
        else:
            self.masked |= self.report
            self.report = set()

    def print(self, kev, show_masked=False, show_description=False):
        if not self.report and not show_masked:
            return
        d = self.derivation
        wl = not self.report

        click.secho('\n{}'.format('-' * 72), dim=wl)
        click.secho('{}\n'.format(d.name), fg='yellow', bold=True, dim=wl)
        if d.store_path:
            click.secho(d.store_path, fg='magenta', dim=wl)

        click.secho(
            '{:50} {:<10} {}'.format(
                'CVE',
                'CVSSv3',
                'Description' if show_description else ''
            ).rstrip(),
            dim=wl
        )
        for v in sorted(self.report, key=vuln_sort_key):
            click.echo(fmt_vuln(v, kev, show_description))
        if show_masked:
            for v in sorted(self.masked, key=vuln_sort_key):
                click.secho("{}  [whitelisted]".format(fmt_vuln(
                    v,
                    kev,
                    show_description
                )), dim=True)

        issues = functools.reduce(
            set.union, (r.issue_url for r in self.rules), set())
        if issues:
            click.secho('\nIssue(s):', fg='cyan', dim=wl)
            for url in issues:
                click.secho(url, fg='cyan', dim=wl)
        for rule in self.rules:
            if rule.comment:
                click.secho('\nComment:', fg='blue', dim=wl)
                for comment in rule.comment:
                    click.secho('* ' + comment, fg='blue', dim=wl)


def output_text(vulns, kev, show_whitelisted=False, show_description=False):
    report = [v for v in vulns if v.report]
    wl = [v for v in vulns if not v.report]

    if not report and not show_whitelisted:
        if wl:
            click.secho('Nothing to show, but {} left out due to whitelisting'.
                        format(len(wl)), fg='blue')
        else:
            click.secho('Found no advisories. Excellent!', fg='green')
        return

    click.secho('{} derivations with active advisories'.format(
        len(report)), fg='red')
    if wl and not show_whitelisted:
        click.secho('{} derivations left out due to whitelisting'.format(
            len(wl)), fg='blue')

    for i in sorted(report, key=attrgetter('derivation')):
        i.print(kev, show_whitelisted, show_description)
    if show_whitelisted:
        for i in sorted(wl, key=attrgetter('derivation')):
            i.print(kev, show_whitelisted, show_description)
    if wl and not show_whitelisted:
        click.secho('\nuse --show-whitelisted to see derivations with only '
                    'whitelisted CVEs', fg='blue')


def output_json(items, kev, show_whitelisted=False):
    out = []
    for i in sorted(items, key=attrgetter('derivation')):
        if not i.report and not show_whitelisted:
            continue
        d = i.derivation
        out.append({
            'name': d.name,
            'pname': d.pname,
            'version': d.version,
            'derivation': d.store_path,
            'affected_by': sorted(v.cve_id for v in i.report),
            'whitelisted': sorted(v.cve_id for v in i.masked),
            'known_exploited': sorted(v.cve_id for v in i.report
                                      if kev.is_known_exploited(v.cve_id)),
            'known_exploited_due_date': {
                v.cve_id: kev.due_date(v.cve_id) for v in i.report
                if kev.is_known_exploited(v.cve_id)
            },
            'cvssv3_basescore': {
                v.cve_id: v.cvssv3
                for v in (i.report | i.masked)
                if v.cvssv3
            },
            'description': {
                v.cve_id: v.description
                for v in (i.report | i.masked)
                if v.description
            },
        })
    print(json.dumps(out, indent=1))


def output(
        items,
        kev,
        json=False,
        show_whitelisted=False,
        show_description=False):
    if json:
        output_json(items, kev, show_whitelisted)
    else:
        output_text(items, kev, show_whitelisted, show_description)
    if any(i.report for i in items):
        return 2
    if show_whitelisted and any(i.masked for i in items):
        return 1
    return 0
