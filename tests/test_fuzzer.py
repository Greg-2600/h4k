# Tests for the lab fuzzer's classification and vector building (no network).
from services.fuzzer import MUTATIONS, LabFuzzer


def test_classify_benign_ok():
    assert LabFuzzer._classify(0, 0.02, "HTTP/1.1 200 OK", True) is None


def test_classify_server_error():
    assert (
        LabFuzzer._classify(0, 0.02, "HTTP/1.1 500 Internal Server Error", True)
        == "server_error"
    )


def test_classify_stack_trace():
    assert (
        LabFuzzer._classify(0, 0.02, "Exception java.lang.NullPointerException", True)
        == "server_error"
    )


def test_classify_teardown():
    assert LabFuzzer._classify(3, 0.01, "", True) == "teardown"


def test_classify_hang():
    assert LabFuzzer._classify(2, 3.0, "", True) == "hang"


def test_classify_resource_unreachable():
    assert LabFuzzer._classify(4, 0.01, "", True) == "resource"


def test_mutation_corpus_nonempty():
    assert len(MUTATIONS) > 0
    # all entries are (label, payload)
    for label, payload in MUTATIONS:
        assert isinstance(label, str)
        assert isinstance(payload, bytes)


def test_build_vector_contains_payload():
    f = LabFuzzer()
    vec = f._build_vector("http://h/", "x", b"PAYLOADXYZ")
    assert b"PAYLOADXYZ" in vec
