"""Run the deterministic AI red-team suite as part of CI."""

from scripts.redteam_agent import run_cases


def test_all_redteam_cases_are_blocked():
    results = run_cases()
    assert len(results) >= 14
    failed = [result for result in results if not result["blocked"]]
    assert not failed, failed


def test_redteam_categories_are_covered():
    categories = {result["category"] for result in run_cases()}
    assert {
        "schema",
        "schema_oversized",
        "path",
        "rule",
        "prompt",
        "rag",
        "rate",
        "audit",
    } <= categories
