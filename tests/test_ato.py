from app.modules.ato.engine import ATOEngine


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


def codes(r):
    return {f.code for f in r.findings}


def make():
    clk = Clock()
    return ATOEngine(window_seconds=300, clock=clk), clk


CHROME_WIN = "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0"
CHROME_WIN_NEWER = "Mozilla/5.0 (Windows NT 10.0) Chrome/126.0"
SAFARI_IOS = "Mozilla/5.0 (iPhone; CPU iPhone OS 17) Safari/604"


def test_cold_start_has_no_anomalies():
    eng, _ = make()
    r = eng.analyze("alice", 0, "203.0.113.5", CHROME_WIN, "IN")
    assert r.score == 0 and any("No history" in n for n in r.notes)


def test_failed_login_burst_scales():
    eng, clk = make()
    scores = []
    for _ in range(3):
        clk.t += 10
        scores.append(eng.analyze("bob", 4).score)
    assert scores == [0, 20, 40]


def test_window_expires_old_failures():
    eng, clk = make()
    eng.analyze("carol", 9)
    clk.t += 400
    assert "failed_burst" not in codes(eng.analyze("carol", 1))


def test_new_country_after_baseline_and_impossible_travel():
    eng, clk = make()
    eng.analyze("dave", 0, "203.0.113.5", CHROME_WIN, "IN", "AS55836")
    clk.t += 600
    r = eng.analyze("dave", 0, "198.51.100.9", CHROME_WIN, "RU", "AS12389")
    assert {"new_country", "impossible_travel", "new_asn", "new_network"} <= codes(r)
    assert r.score >= 60


def test_browser_version_bump_is_not_a_new_device():
    eng, clk = make()
    eng.analyze("erin", 0, "203.0.113.5", CHROME_WIN, "IN")
    clk.t += 86_400
    assert "new_device" not in codes(eng.analyze("erin", 0, "203.0.113.5", CHROME_WIN_NEWER, "IN"))
    assert "new_device" in codes(eng.analyze("erin", 0, "203.0.113.5", SAFARI_IOS, "IN"))


def test_risky_event_does_not_poison_baseline():
    eng, clk = make()
    eng.analyze("frank", 0, "203.0.113.5", CHROME_WIN, "IN")
    clk.t += 600
    eng.analyze("frank", 0, "198.51.100.9", CHROME_WIN, "RU")  # flagged (>= 40)
    clk.t += 4000
    assert "new_country" in codes(eng.analyze("frank", 0, "198.51.100.9", CHROME_WIN, "RU"))


def test_usernames_are_case_insensitive_and_users_are_bounded():
    eng, clk = make()
    eng.analyze("Grace", 0, None, CHROME_WIN, "IN")
    assert not any("No history" in n for n in eng.analyze("grace", 0, None, CHROME_WIN, "IN").notes)
    small = ATOEngine(max_users=3, clock=clk)
    for i in range(10):
        small.analyze(f"u{i}")
    assert len(small._users) == 3


def test_account_ref_does_not_expose_username():
    eng, _ = make()
    ref = eng.analyze("hannah@example.com").evidence["account_ref"]
    assert "hannah" not in ref
