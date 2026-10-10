---
license: cc-by-4.0
task_categories:
- question-answering
- text-classification
- text-generation
- sentence-similarity
language:
- en
tags:
- telemetry
- edr
- endpoint
- deception
- malware
- adversarial
- attacker
- threat
- intrusion
- processes
- filesystem
- network
- connections
- hashes
- dns
- pids
- security
- detection
- forensics
- hunting
- metadata
- threat-intelligence
- cybersecurity
- infosec
- cybersecurityinfosec
- active-directory
- process-tree
- detection-engineering
- threat-hunting
- siem
- labeled
- behavioral
- anomaly-detection
- ground-truth
- real-world
pretty_name: Long-term Malware Detonation EDR Telemetry Samples
size_categories:
- n<1K
viewer: false
---

This dataset contains raw Endpoint Detection & Response (EDR) telemetry captured during controlled Deception.Pro malware sandbox operations on an enterprise Active Directory network. Unlike most malware sandboxes — which detonate samples for roughly 30 minutes — our operations run for hours or days per analysis, capturing the full arc of adversary behavior. The data represents a full-fidelity snapshot of system activity recorded while threat actors interacted with a live deception environment, making it a rare, real-world ground-truth record of malicious activity observed alongside authentic benign baseline noise.
The dataset captures the complete process execution tree of a live Windows system, enriched with network telemetry, DNS resolution activity, and file system interaction events. Because it was collected in an extended malware sandbox context, it contains authentic attacker tooling artifacts (including malware executable telemetry, persistence mechanisms, and C2 communications) co-mingled with normal system traffic — making it uniquely valuable for training detection models, validating SIEM rules, and threat hunting research.

Dataset Features
The dataset is structured as a hierarchical process tree with each node representing a process and containing the following fields:
- process_list: Top-level key; a nested dictionary keyed by Process ID (PID).
- children: Nested child processes spawned by the parent, preserving the full parent-child execution chain
- cmd: Full command-line string used to launch the process.
- time: Human-readable UTC timestamp of process creation (YYYY-MM-DD HH:MM:SS).
- file_path: Absolute filesystem path of the executing binary.
- network.dns_requests[]: Array of DNS queries made by the process, including DOMAIN_NAME, CNAME, DNS_TYPE, MESSAGE_ID, and PROCESS_ID.
- network.network_connections[]: Array of network connection events, each containing a NETWORK_ACTIVITY array with SOURCE, DESTINATION (IP + port), PROTOCOL, IS_OUTGOING flag, TIMESTAMP, and optional ENRICHMENT.
- documents[]: Files opened or indexed by the process, including the full file_path, SHA-256 hash, and timestamp.

Distribution
Format: Each operation has a single JSON file (either JSON or GZIP JSON)

This dataset is well-suited for:
- Detection Engineering: Writing and validating SIEM/EDR detection rules against real attacker behavior.
- ML/AI Model Training: Supervised or unsupervised models for process anomaly detection, malicious command-line classification, or network behavior baselining.
- Threat Intelligence: Extracting IOCs (file hashes, IPs, domains, malware paths) from a confirmed compromise scenario.
- Red Team / Blue Team Training: Realistic exercise data replicating attacker TTPs within a live Windows environment.
- Academic Research: Behavioral analysis of malware families, persistence mechanisms, and C2 patterns in controlled settings.

Coverage
The dataset captures EDR Telemetry from an infected, domain joined Windows endpoint over an extended observation window. Coverage includes:
- Full process ancestry: from kernel-level system processes through to attacker-dropped binaries.
- Both benign and malicious activity: Windows Update, DHCP, DNS cache, Chrome browsing, and Search services appear alongside confirmed threat actor tooling.
- Multiple attacker-dropped executables: See the entire attack chain to include multiple infection stages, Active Directory reconnaisance and lateral movement attempts.
- Network telemetry: Spanning both internal RFC1918 addresses and external IP destinations over TCP/UDP.
- File hash coverage: SHA-256 hashes present for all document/file interaction events, enabling direct cross-referencing with threat intelligence platforms (VirusTotal, MISP, etc.).

Examples of intended users and their use cases:
- Security Researchers: Behavioral analysis of multi-stage malware execution chains.
- Detection Engineers: Building and testing SIEM/EDR detection rules against authentic attacker TTPs.
- Data Scientists / ML Engineers: Training process-level anomaly detection or malicious binary classification models.
- Threat Intelligence Analysts: IOC extraction — file hashes, C2 IPs, suspicious domains, persistence paths.
- Red Team Operators: Studying attacker staging, naming conventions, and lateral movement patterns.
- Cybersecurity Educators: Providing students with realistic, sanitized incident data for hands-on exercises.
- CTI Platform Developers: Testing ingestion pipelines and enrichment workflows on real telemetry.

Need more of this type of data?
Check out our listing at https://www.opendatabay.com/data/dataset/7ac14f31-34a3-4c26-bbe3-e09c3f6ff82a
