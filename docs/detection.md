# How detection works

This page explains the detection design in plain terms. It is the reference for anyone tuning rules, reading an incident, or writing about the method.

## From events to incidents

1. **Events** arrive through the signed ingestion API and are mapped into one common format.
2. **Detectors** read each event. A detector is either a rule or an anomaly model. A detector that finds something raises an **alert**.
3. **Correlation** groups alerts that share a machine or a person, within a time window, into one **incident**.
4. Each incident gets one **confidence** score and a **band**: low, medium or high.

Only the band decides what happens next.

| Band | What happens |
| --- | --- |
| Low | Kept for tuning. Not queued, not forwarded. |
| Medium | Goes to the analyst queue and is forwarded to the SIEM. |
| High | As medium, and an analyst may approve isolation of the machines it names. |

## Rules

Rules are rows in the `rules` table. Each has a kind:

- **match**: one event that meets every condition, such as a command that deletes shadow copies.
- **threshold**: enough matching events for one entity inside a time window, such as thirty file renames on one machine in a minute.
- **new value**: a value an entity has never used before, such as a medical device contacting a host outside its usual set.

Every rule carries a confidence between 0 and 1: how likely an alert from this rule alone is to be a real problem. Every rule also names a MITRE ATT&CK technique.

## Anomaly models

Three models watch one kind of entity each, over fixed windows of time.

| Model | Entity | Window | What it summarises |
| --- | --- | --- | --- |
| Record access | Member of staff | 15 minutes | Patients opened, how many outside their own department, how that compares with their own history and their peers, and whether the hour is unusual for them |
| Endpoint behaviour | Machine | 1 minute | Files written, renamed and deleted, file types touched, programs started, programs new to that kind of machine |
| Device traffic | Medical device | 5 minutes | Connections, hosts contacted, hosts never contacted before, ports, bytes, peak packet rate |

Each model is an Isolation Forest trained on recent activity. It needs no labelled attacks. A window raises an alert when two things hold:

1. It is unusual. Either the forest isolates it quickly, or one of its features exceeds anything seen in training. The second test exists because a forest cannot see a value outside the range it was trained on.
2. At least one feature sits far outside the normal range for that peer group, measured in robust deviations.

Confidence grows with that distance. Every alert lists the features that drove it, with the value seen and the typical value.

## Confidence and bands

Detectors are treated as independent witnesses. If one detector is 60% confident and another is 50% confident, the chance that at least one is right is 1 minus (0.4 times 0.5), which is 80%. Several alerts from the same detector count once.

One safeguard sits on top. **An incident cannot be high unless at least two independent log sources agree.** A single faulty or spoofed sensor can therefore never trigger an isolation offer by itself. This is why record snooping, which only the EHR audit log can see, stays at medium.

All of these numbers are rows in the settings table.

## Learning from analysts

When an analyst dismisses an incident as expected activity, each detector that contributed learns, for that entity only:

| Detector | What changes |
| --- | --- |
| New value rule | The value joins that entity's baseline. After the same value has been dismissed for three entities, it becomes normal for all. |
| Threshold rule | That entity needs one and a half times the dismissed count before the rule fires again. |
| Match rule | The rule is silenced for that entity. |
| Model | That entity must sit further from normal than the dismissed window. The window also joins every later training run as a heavily weighted normal example, which widens the normal range for that kind of machine or person. |

Every change is listed on the Rules page and can be undone there. A confirmed incident does the opposite: its activity is kept out of future training.

## What is deliberately simple

- Correlation links alerts through shared machines and people. Two unrelated problems on the same desk in the same hour can land in one incident.
- The models retrain on a schedule from recent activity. They do not yet account for weekly or seasonal patterns.
- Feedback is powerful. An analyst who wrongly dismisses a real attack as expected activity teaches the detectors to tolerate it for that entity. The audit log records who did so.
