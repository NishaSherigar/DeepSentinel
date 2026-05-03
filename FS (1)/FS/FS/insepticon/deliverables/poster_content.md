# Poster Content

## Title
DeepSentinel: A Hybrid SIEM for Insider Threat Detection

## Authors
<Student Name 1>, <Student Name 2>, <Student Name 3>, <Student Name 4>, <Mentor Name>

## Introduction
DeepSentinel is a Security Information and Event Management platform built to detect insider threats in enterprise environments. The system monitors endpoint and user activity in real time, including file access, USB events, process launches, email behavior, session activity, HTTP requests, and sensitive resource usage. Unlike traditional log collectors, DeepSentinel combines behavioral analytics with machine learning to identify subtle misuse patterns that may not match fixed signatures. The platform also adds operational features such as incident grouping, audit trails, role-based access control, and real-time notifications, making it useful for SOC teams, compliance officers, and incident responders.

## Problem Statement
Insider threats are difficult to detect because valid users can misuse approved access without triggering conventional perimeter defenses. Organizations need a system that can correlate endpoint activity, assign interpretable risk scores, and respond quickly enough to reduce damage. The objective of this work is to build a practical SIEM that performs real-time monitoring, anomaly detection, alert generation, and investigation support for insider threat scenarios.

## Methodology
DeepSentinel follows a hybrid detection pipeline. Windows agents collect endpoint events and forward them to a Flask server through the `/receive_log` API. Incoming events are validated, normalized, and transformed into 11 behavioral features. The ML stack uses MinMax scaling, Isolation Forest pre-screening, and a PyTorch autoencoder for anomaly scoring. A heuristic layer evaluates contextual signals such as after-hours access, abnormal file creation volume, sensitive path interaction, and suspicious process activity. These signals are blended into a final risk score with a human-readable explanation. Supporting modules handle UEBA, peer analysis, incident management, audit logging, honeypots, screen recording, and automated notification.

## Results and Discussion
Project validation indicates that the framework achieves about 80% detection accuracy while maintaining near real-time performance. Average event processing latency is approximately 100-150 ms, and the server handles close to 1,000 events per minute in a single-node setup. The hybrid scoring approach reduces dependence on either pure signatures or pure ML by combining contextual rules with anomaly models. This improves analyst trust because alerts include both a score and an explanation. The architecture is also operationally practical, since incidents, user risk trends, and audit evidence are preserved for investigation and compliance reporting.

## Conclusion
DeepSentinel demonstrates that insider threat monitoring is more effective when behavioral analytics, anomaly detection, and operational response are designed as a single workflow instead of disconnected tools. The system provides continuous event collection, interpretable risk scoring, incident grouping, and security automation within one enterprise-ready SIEM framework. Results from the current implementation show that the platform can deliver useful accuracy and low latency for real-time monitoring. The project also highlights the importance of explainability, because risk scores alone are not sufficient for analyst action. Future work can focus on larger-scale evaluation, richer email and NLP-based threat understanding, adaptive threshold learning, and broader deployment across multi-LAN enterprise environments.

## Key Metrics Table
Metric
Validation accuracy: ~80%
Average event latency: 100-150 ms
Peak throughput: ~1,000 events/min
Behavioral features: 11
ML models in pipeline: 3
Primary event categories: 9+
Risk scoring: Hybrid ML + heuristics
Storage model: Append-only JSONL
Deployment scope: Multi-agent, multi-LAN

## References
[1] DeepSentinel Project Documentation, "DeepContext.md," Version 4.0, Apr. 1, 2026.

[2] F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation Forest," in Proceedings of the 2008 IEEE International Conference on Data Mining, 2008, pp. 413-422.

[3] M. Sakurada and T. Yairi, "Anomaly Detection Using Autoencoders with Nonlinear Dimensionality Reduction," in Proceedings of the MLSDA 2014 2nd Workshop on Machine Learning for Sensory Data Analysis, 2014, pp. 4-11.

[4] A. Paszke et al., "PyTorch: An Imperative Style, High-Performance Deep Learning Library," in Advances in Neural Information Processing Systems 32, 2019.
