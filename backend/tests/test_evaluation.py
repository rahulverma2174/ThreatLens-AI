from scripts.evaluate_detection import build_dataset, calculate_metrics


def test_synthetic_evaluation_dataset_and_metrics() -> None:
    rows = build_dataset()
    assert len(rows) == 35
    assert sum(row["ground_truth"] == "attack" for row in rows) == 15
    assert {row["scenario"] for row in rows} == {
        "routine-spread-out",
        "brute-force",
        "password-spraying-indicator",
        "success-after-failures",
        "account-multiple-source-ips",
    }

    metrics = calculate_metrics(
        [True, True, False, False],
        [True, False, True, False],
    )
    assert metrics == {
        "true_positive": 1,
        "false_positive": 1,
        "true_negative": 1,
        "false_negative": 1,
        "precision": 0.5,
        "recall": 0.5,
        "f1": 0.5,
        "false_positive_rate": 0.5,
    }
