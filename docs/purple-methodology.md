# Purple correlation methodology

`secram.modules.purple.correlation.correlate()` correlates completed task windows with valid telemetry dictionaries. It is an offline correlation aid, not a compromise detector. The output contains a chronological `timeline`, conservative `metrics`, and de-duplicated `limitations`.

## Linkage rules

A task is exercised only when its state is `succeeded`, its start and finish timestamps are timezone-aware, and its result is not failed, cancelled, partial, or inconclusive. Failed, cancelled, and inconclusive tasks are excluded from the executed-test denominator. Telemetry must carry the shared contract fields, including a UUID `id`, UTC-aware `observed_at`, severity, details, and literal-IP endpoint values when present. Invalid, wrong-assessment, wrong-target, or out-of-window events are ignored.

An event with an explicit matching `task_id` is the only verified task linkage. An event without that linkage can match only by the same assessment, endpoint, port when supplied, and observation time inside the task window; this is a **candidate** correlation and does not prove causation. A missing `rule_id` remains an observation and is never a detected attack. A detection requires all three conditions: explicit matching `task_id`, non-null `rule_id`, and an explicitly trusted complete coverage record that applies to the task.

## Coverage and metrics

Coverage is unknown by default. A not-detected result is emitted only when coverage explicitly says it is complete and trusted, includes a valid start/finish window, and names applicable `task_ids` or `observed_operations`. Active `psutil` polling does not establish packet or scan coverage. Consequently, no alerts with unknown coverage remain `unknown`; no alerts with applicable trusted complete coverage are `not_detected`.

The detection-rate denominator is the number of applicable completed, conclusive tasks in trusted coverage. It is `None` when that denominator is not measurable. The false-positive rate is `None` unless coverage supplies explicitly reviewed negative data with a positive true denominator and a bounded false-positive count; it is never defaulted to zero.

Only `nmap.tcp_scan` is mapped to MITRE ATT&CK **T1046 — Network Service Discovery**. Unsupported operations have no invented technique mapping. Timestamps are retained from task and telemetry inputs; the correlator does not fabricate observations or assert security findings.
