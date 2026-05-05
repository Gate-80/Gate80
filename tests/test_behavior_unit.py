from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from proxy.behaviour_class import RequestSignal, SessionWindow, classify_behavior
from proxy.main import build_session_summary


def make_signal(timestamp, path, status_code, think_time_ms, method="GET"):
    signal = RequestSignal(
        timestamp=timestamp,
        path=path,
        status_code=status_code,
        think_time_ms=think_time_ms,
    )
    signal.method = method
    return signal


def make_window(signals):
    window = SessionWindow()
    for signal in signals:
        window.add(signal)
    return window


def test_single_normal_get_feature_extraction():
    window = make_window([
        make_signal(1000.0, "/api/v1/balance", 200, 0, method="GET"),
    ])

    features = window.extract_window_features()
    summary = build_session_summary("guest:test-normal", window)

    print("\nFEATURES:", features)
    print("SUMMARY:", summary.model_dump())

    assert features["requests_per_minute"] == 0
    assert features["error_ratio"] == 0
    assert features["unique_endpoints"] == 1
    assert features["wallet_action_ratio"] == 0
    assert features["transfer_count"] == 0

    assert summary.signals.request_rate == pytest.approx(1.0)
    assert summary.signals.unique_endpoints == 1
    assert summary.signals.failed_auth_ratio == 0
    assert summary.signals.status_404_ratio == 0
    assert summary.signals.method_diversity == 1


def test_rapid_auth_failures_classify_as_brute_force():
    signals = [
        make_signal(1000.0 + index * 0.1, "/auth/sign-in", 401, 100, method="POST")
        for index in range(6)
    ]
    window = make_window(signals)
    classification = classify_behavior(window)

    print("\nCLASSIFICATION:", classification)
    print("FEATURES:", window.extract_window_features())
    print("CUMULATIVE:", window.cumulative_scores)

    assert classification == "brute_force"


def test_admin_and_404_probing_classify_as_scanning():
    signals = [
        make_signal(2000.0, "/admin/users", 404, 900),
        make_signal(2000.4, "/admin/wallets", 404, 900),
        make_signal(2000.8, "/admin/transactions", 404, 900),
        make_signal(2001.2, "/nonexistent-1", 404, 900),
        make_signal(2001.6, "/nonexistent-2", 404, 900),
        make_signal(2002.0, "/nonexistent-3", 404, 900),
    ]
    window = make_window(signals)
    classification = classify_behavior(window)

    print("\nCLASSIFICATION:", classification)
    print("FEATURES:", window.extract_window_features())
    print("CUMULATIVE:", window.cumulative_scores)

    assert classification == "scanning"


def test_repeated_wallet_transfers_classify_as_fraud():
    signals = [
        make_signal(3000.0 + index * 0.2, "/wallet/transfer", 200, 700, method="POST")
        for index in range(6)
    ]
    window = make_window(signals)
    classification = classify_behavior(window)

    print("\nCLASSIFICATION:", classification)
    print("FEATURES:", window.extract_window_features())
    print("CUMULATIVE:", window.cumulative_scores)

    assert classification == "fraud"
