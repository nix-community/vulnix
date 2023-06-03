from vulnix.vulnerability import Vulnerability, Node


def test_kev(kev):
    kev.update()
    assert kev.is_known_exploited("CVE-1988-5678")
    assert kev.is_known_exploited("CVE-1988-1234")
    assert not kev.is_known_exploited("CVE-1988-7777")

    assert kev.due_date("CVE-1988-1234") == "1988-12-02"
    assert kev.is_past_due("CVE-1988-1234")
