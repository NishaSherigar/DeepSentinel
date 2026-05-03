# DeepSentinel: A Hybrid SIEM Framework for Insider Threat Detection Using Behavioral Analytics and Machine Learning

**Authors:** `<Student Name 1>`, `<Student Name 2>`, `<Student Name 3>`, `<Student Name 4>`
**Mentor:** `<Mentor Name>`
**Affiliation:** `<Department / Institution Name>`

## Abstract

Insider threats remain one of the most difficult cybersecurity problems because malicious or negligent actions are performed by authenticated users whose behavior may initially appear legitimate. This project presents **DeepSentinel**, an enterprise-grade Security Information and Event Management (SIEM) framework designed to detect insider threats through continuous endpoint monitoring, behavioral analytics, hybrid risk scoring, and real-time incident response. The system collects heterogeneous activity data from distributed Windows agents, including file operations, USB access, process execution, email activity, session events, HTTP requests, and sensitive resource access. These events are normalized at a centralized Flask-based server and evaluated using a layered detection pipeline that combines rule-driven heuristics with machine learning models.

The proposed threat engine integrates an 11-feature MinMaxScaler, an Isolation Forest model for anomaly pre-screening, and a PyTorch autoencoder for reconstruction-based anomaly detection. To improve operational reliability, model outputs are blended with contextual indicators such as after-hours activity, threshold violations, and policy-sensitive actions to produce an interpretable risk score and alert explanation. Beyond detection, DeepSentinel includes incident grouping, audit logging, user risk scoring, role-based access control, multi-channel notifications, honeypot-based deception, and automated containment support.

Experimental validation reported in the project context shows approximately **80% detection accuracy**, average event processing latency of **100-150 ms**, and throughput near **1,000 events per minute** on a single server. These results indicate that DeepSentinel can support near real-time insider threat monitoring while preserving explainability and operational usability. The framework demonstrates how hybrid analytics can strengthen organizational visibility, reduce alert blind spots, and provide a scalable foundation for security operations and compliance-driven environments.

## Keywords

SIEM, Insider Threat Detection, UEBA, Behavioral Analytics, Isolation Forest, Autoencoder, Security Monitoring
