from operator import attrgetter
import click
import functools
import json


def cve_url(cve_id):
    return 'https://nvd.nist.gov/vuln/detail/' + cve_id


class Filtered:
    """Derivation with whitelist filtering applied.

    Initially, all CVEs are in the `report` set. When whitelist rules
    are added via `add()`, matching CVEs are moved into the `masked`
    set. Output formatting depends on which of these sets have any
    members.
    """

    until = None

    def __init__(self, derivation):
        self.derivation = derivation
        self.rules = []
        self.report = derivation.affected_by
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
                mask = self.report & wl_rule.cve
                self.report -= mask
                self.masked |= mask
        else:
            self.masked |= self.report
            self.report = set()

    def print(self, verbose=0, show_masked=False):
        if not self.report and not show_masked:
            return
        _fmt = cve_url if verbose else lambda x: x
        d = self.derivation
        wl = not self.report

        click.secho('\n{}'.format('-' * 72), dim=wl)
        click.secho('{}\n'.format(d.name), fg='yellow', bold=True, dim=wl)
        if verbose and d.store_path:
            click.secho(d.store_path, fg='magenta', dim=wl)

        click.secho("CVEs:", dim=wl)
        for cve_id in sorted(self.report):
            click.echo("\t" + _fmt(cve_id))
        if show_masked:
            for cve_id in sorted(self.masked):
                click.secho("\t{} (whitelisted)".format(_fmt(cve_id)),
                            dim=True)

        if not verbose:
            return
        issues = functools.reduce(
            set.union, (r.issue_url for r in self.rules), set())
        if issues:
            click.secho('Issue(s):', fg='cyan', dim=wl)
            for url in issues:
                click.secho('\t' + url, fg='cyan', dim=wl)
        for rule in self.rules:
            if rule.comment:
                click.secho('Comment:', fg='blue', dim=wl)
                for comment in rule.comment:
                    click.secho('\t' + comment, fg='blue', dim=wl)


def output_text(items, show_whitelisted=False, verbose=False):
    report = [i for i in items if i.report]
    wl = [i for i in items if not i.report]

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
        i.print(verbose, show_whitelisted)
    if show_whitelisted:
        for i in sorted(wl, key=attrgetter('derivation')):
            i.print(verbose, show_whitelisted)
    if wl and not show_whitelisted:
        click.secho('\nuse --show-whitelisted to see derivations with only '
                    'whitelisted CVEs', fg='blue')


def output_json(items, show_whitelisted=False):
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
            'affected_by': sorted(list(i.report)),
            'whitelisted': sorted(list(i.masked)),
        })
    print(json.dumps(out, indent=1))


def output(items, json=False, show_whitelisted=False, verbose=False):
    if json:
        output_json(items, show_whitelisted)
    else:
        output_text(items, show_whitelisted, verbose)
    if any(i.report for i in items):
        return 2
    if show_whitelisted and any(i.masked for i in items):
        return 1
    return 0
