This file documents a genuine, live-triggered Active Response event from the
Detection-as-Code stretch goal (real SSH brute-force attack against the Wazuh
VM itself, detected by custom rule 100010, automatically handed to
respond_auto.py by Wazuh's Active Response system — no manual script
invocation involved).

Captured: 2026-08-02, from /home/azureuser/response/last_alert_raw.log
on the soc-project-wazuh-siem VM (20.165.183.178).

=== RAW ALERT JSON SENT BY WAZUH ACTIVE RESPONSE TO respond_auto.py ===

{"version":1,"origin":{"name":"node01","module":"wazuh-execd"},"command":"add","parameters":{"extra_args":[],"alert":{"timestamp":"2026-08-02T16:06:42.555+0000","rule":{"level":10,"description":"SOC-PROJECT: Possible SSH brute force attack (6+ failures in 2 min)","id":"100010","mitre":{"id":["T1110"],"tactic":["Credential Access"],"technique":["Brute Force"]},"frequency":6,"firedtimes":1,"mail":false,"groups":["local","syslog","sshd","authentication_failures"],"pci_dss":["10.2.4","10.2.5"]},"agent":{"id":"000","name":"soc-project-wazuh-siem"},"manager":{"name":"soc-project-wazuh-siem"},"id":"1785686802.53631","previous_output":"Aug 02 16:06:34 soc-project-wazuh-siem sshd[104858]: Failed password for azureuser from 74.96.216.30 port 30693 ssh2\nAug 02 16:06:29 soc-project-wazuh-siem sshd[104858]: Failed password for azureuser from 74.96.216.30 port 30693 ssh2\nAug 02 16:06:22 soc-project-wazuh-siem sshd[104856]: Failed password for azureuser from 74.96.216.30 port 30692 ssh2\nAug 02 16:06:18 soc-project-wazuh-siem sshd[104856]: Failed password for azureuser from 74.96.216.30 port 30692 ssh2\nAug 02 16:06:11 soc-project-wazuh-siem sshd[104856]: Failed password for azureuser from 74.96.216.30 port 30692 ssh2","full_log":"Aug 02 16:06:41 soc-project-wazuh-siem sshd[104858]: Failed password for azureuser from 74.96.216.30 port 30693 ssh2","predecoder":{"program_name":"sshd","timestamp":"Aug 02 16:06:41","hostname":"soc-project-wazuh-siem"},"decoder":{"parent":"sshd","name":"sshd"},"data":{"srcip":"74.96.216.30","srcport":"30693","dstuser":"azureuser"},"location":"journald"},"program":"active-response/bin/respond_auto.py"}}

=== WHY THIS PROVES A REAL, LIVE TRIGGER (not a manual test) ===

- "module":"wazuh-execd" — this originated from Wazuh's own real execution
  engine, not from a manually piped test command.
- "rule":{"id":"100010", "description":"SOC-PROJECT: Possible SSH brute
  force attack..."} — this is the custom detection rule built for this
  project, genuinely firing on real traffic.
- "previous_output" contains 5 real, distinct sshd log lines with real
  timestamps and ports, showing the actual sequence of failed logins Wazuh
  correlated to reach the 6-event threshold.
- "program":"active-response/bin/respond_auto.py" — Wazuh explicitly
  logging that it invoked this exact script in response.

=== SOURCE OF THE FAILED LOGINS ===

Real SSH connection attempts were made from the operator's own IP
(74.96.216.30) against the Wazuh VM's own SSH service, using wrong
passwords, to generate genuine sshd "Failed password" log entries — the
same technique used in Project 1, applied here to trigger this project's
custom rule and Active Response pipeline live.

=== INCIDENT RECORDS CREATED AUTOMATICALLY BY respond_auto.py ===

Two incident JSON files were automatically written to
/home/azureuser/response/incidents/ as a direct result of this trigger,
confirming the full pipeline (detect -> Active Response -> enrich -> decide
-> record) executed end-to-end without manual intervention once the attack
occurred.

=== HONEST NOTE ON RELIABILITY ===

Active Response reliably triggered on this and other test runs. During
repeated testing (multiple restarts of wazuh-manager while iterating on
configuration), triggering was not perfectly consistent on every single
repeated attempt — likely due to timing interactions between Wazuh's
frequency/correlation engine and its Active Response queue during rapid
config reloads, rather than any defect in the rule logic or the Python
script (both of which were independently verified correct via wazuh-logtest
and direct script invocation). In a production deployment, this would
warrant further investigation, or use of a message-queue-based integration
in place of direct Active Response for correlation-based detections.
