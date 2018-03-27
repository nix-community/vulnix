import pkg_resources
from vulnix.whitelist import Whitelist, WhitelistItem


def test_from_yaml(whitelist_yaml):
    wl = Whitelist.from_yaml(whitelist_yaml)
    assert len(wl) == 5
    assert wl[0].cve == set(['CVE-2015-2504', 'CVE-2015-7696'])
    assert wl[0].name == WhitelistItem.ANY
    assert wl[0].version == WhitelistItem.ANY
    assert wl[0].issue == WhitelistItem.ANY
    assert wl[0].comment == WhitelistItem.ANY

    assert wl[1].name == 'libxslt'

    assert wl[4].issue == 'https://fb.flyingcircus.io/f/cases/26909/'
