from conftest import load

from vulnix.vulnerability import Node, Vulnerability


def test_update(nvd):
    nvd.update()
    assert len(nvd._root["advisory"]) == 835
    cve = nvd.by_id("CVE-2010-0748")
    assert cve == Vulnerability.parse(load("CVE-2010-0748"))
    assert cve == nvd.by_product("transmission")[0]


def test_parse_vuln():
    v = Vulnerability.parse(load("CVE-2019-10160"))
    assert v.cve_id == "CVE-2019-10160"
    assert v.nodes == [
        Node("python", "python", "3.5"),
        Node("python", "python", "3.6"),
        Node("python", "python", "3.7"),
        Node("python", "python", [">=3.8.0a4", "<=3.8.0b1"]),
    ]
