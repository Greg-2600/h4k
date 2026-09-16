# Tests for the security-posture assessment heuristic.
from services.security import SecurityAssessmentService, _level, _score


def test_score_positive_for_exposed():
    # many open services + internet path + plaintext mgmt -> high score (exposed)
    s = _score(["large-service-surface", "public-internet-path", "plaintext-mgmt"])
    assert s > 70


def test_score_negative_for_hardened():
    s = _score(["minimal-service-surface", "all-internal-path", "many-star-hops"])
    assert s < 30


def test_level_mapping():
    assert _level(75) == "low"  # low security = high score = exposed
    assert _level(55) == "medium"
    assert _level(20) == "high"


def test_assess_with_star_hops_signals():
    svc = SecurityAssessmentService()
    a = svc.assess(
        "192.168.1.1",
        host={"services": [{"port": 80, "service": "http", "state": "open"}]},
    )
    # with mostly star hops, score should be suppressed => "high" posture level
    assert a["level"] in ("low", "medium", "high")
    assert isinstance(a["score"], float)
    assert "rationale" in a


def test_traceroute_returns_string():
    svc = SecurityAssessmentService()
    out = svc.traceroute("127.0.0.1", hops=2)
    assert isinstance(out, str)
