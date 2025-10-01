# KQL-Threat-Detection-Hub
KQL Threat Detection Queries for Microsoft Defender XDR, Microsoft Sentinel, and the wider Microsoft security stack.

**Purpose:** Share clear, reusable KQL that boosts real-world detection coverage using Microsoft security logs. Many suspicious activities don’t alert by default—but they can be surfaced through telemetry. This repository focuses on practical **Detection Rules**, **Hunting Queries**, and **Visualizations** that analysts can understand and adapt quickly.

## What’s included

* **Detections:** Production-oriented rules mapped to MITRE ATT&CK with data requirements and tuning notes.
* **Hunting:** Pivot-friendly queries to explore hypotheses and validate leads.
* **Visualizations:** KQL snippets designed to power workbooks and quick situational views.
* **Context:** Each item explains the intent, required data sources, and expected outcomes.

## How to use

* Validate in your tenant before enabling in production.
* Confirm data sources (e.g., Defender XDR tables, Windows events, network telemetry).
* Tune thresholds, allowlists, and environment-specific paths as needed.
* Track maturity: proposed → testing → ready.

## Contributing

PRs are welcome. Please include: purpose, data sources, ATT&CK mapping, validation notes, and any known false positives.

## Attribution & contact

Free to use. A shout-out is appreciated when sharing or reusing: **LinkedIn: [Omar Zayed](https://www.linkedin.com/in/omartarekzayed/)**.
Presenting this work as your own without credit is not allowed.

**OZ-KQL Hunting • Defender XDR KQLs • Sentinel KQLs**

**License:** MIT. For defensive and authorized research only.
