from freezegun import freeze_time


def test_kev(kev):
    kev.update()
    assert kev.is_known_exploited("CVE-1988-5678")
    assert kev.is_known_exploited("CVE-1988-1234")
    assert not kev.is_known_exploited("CVE-1988-7777")

    assert kev.due_date("CVE-1988-1234") == "1988-12-02"
    assert kev.is_past_due("CVE-1988-1234")


@freeze_time("1988-12-02 14:30:00")
def test_cve_due_today_is_not_past_due(kev):
    kev.update()
    assert kev.is_known_exploited("CVE-1988-1234")
    # The CVE's due_date is "1988-12-02" (today's date)
    assert kev.is_past_due("CVE-1988-1234") is False
