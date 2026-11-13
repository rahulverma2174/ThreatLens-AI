# Local behavior and anomaly analysis

`app.services.behavior` summarizes up to 5,000 locally stored events over a
configurable 1–720 hour window. User and source profiles include event volume,
failure rate, distinct identities/IPs, common UTC hours, and events occurring
in low-frequency hours. Profiles with fewer than five observations are not
classified for unusual-hour counts.

`app.services.anomaly.score_events` uses up to 500 recent events. Pandas
engineers source frequency, source failure count, username frequency, outcome,
and UTC event hour; NumPy prepares the feature matrix for a CPU-only
scikit-learn Isolation Forest (`n_jobs=1`, fixed random seed). At least 10
events are required for model inference.

`app.services.risk_scoring` adds interpretable local behavior, rule, analyst
blocklist, and optional model factors, caps the sum at 100, and persists each
analysis run. The API separately reports anomaly classification so that a
model signal is not confused with a confirmed incident. Analysis run comparisons
are available only for locally retained assessment records.

Evaluation scenarios and the measured rule/model metrics are documented in the
project README and can be regenerated with
`cd backend && .venv/bin/python -m scripts.evaluate_detection`.
