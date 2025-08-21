from conftest import load

from vulnix.vulnerability import Node, Vulnerability


def test_update(nvd):
    # pylint: disable=protected-access
    nvd.update()
    assert len(nvd._root["advisory"]) == 26
    cve = nvd.by_id("CVE-2010-0748")
    assert cve == Vulnerability.parse(load("CVE-2010-0748"))
    assert cve == nvd.by_product("transmission")[0]


def test_parse_vuln():
    v = Vulnerability.parse(load("CVE-2019-10160"))
    assert v.cve_id == "CVE-2019-10160"
    assert v.nodes == [
        Node("python", "python", [">=2.7.0", "<2.7.17"]),
        Node("python", "python", [">=3.5.0", "<3.5.8"]),
        Node("python", "python", [">=3.6.0", "<3.6.9"]),
        Node("python", "python", [">=3.7.0", "<3.7.4"]),
        Node("python", "python", "3.8.0-alpha4"),
        Node("python", "python", "3.8.0-beta1"),
        Node("redhat", "virtualization", "4.0"),
    ]
