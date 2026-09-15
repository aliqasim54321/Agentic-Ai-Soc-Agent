# Agentic-Ai-Soc-Agent

# 🤖 Agentic AI SOC Agent

An AI-assisted SOC project that converts natural-language threat-hunting requests into structured investigation parameters, analyzes security logs, maps findings to **MITRE ATT&CK**, and supports human-approved endpoint remediation.

---

## 📌 Project Overview

The goal of this project is to explore how Agentic AI can assist SOC analysts with:

- Natural-language threat-hunt requests
- Structured query parameter generation
- KQL-based investigations
- Microsoft Defender for Endpoint telemetry
- MITRE ATT&CK mapping
- IOC extraction
- Confidence-based threat findings
- Human-approved remediation actions

### Example Request

```text
I'm worried that windows-target-1 might have been maliciously logged into in the last few days.
```

The agent converts the request into structured parameters such as:

```json
{
  "table_name": "DeviceProcessEvents",
  "device_name": "windows-target-1",
  "time_range_hours": 24,
  "about_individual_host": true
}
```

These parameters can then be used to build and execute a KQL query.

---

## 🧠 Workflow

```text
Analyst Request
      ↓
AI extracts query parameters
      ↓
KQL Query
      ↓
Security Logs
      ↓
Threat Analysis
      ↓
MITRE ATT&CK + IOCs + Confidence
      ↓
Recommended Action
      ↓
Human Approval
      ↓
Optional Endpoint Isolation
```

---

## 🔍 Threat Hunting

The agent uses table-specific guidance for different data sources.

- **DeviceProcessEvents** → PowerShell abuse, LOLBins, suspicious processes
- **DeviceNetworkEvents** → Suspicious IPs, rare ports, beaconing
- **SigninLogs** → Risky sign-ins, password spray, impossible travel
- **AzureActivity** → Role changes, privilege escalation, suspicious deployments

Findings include:

- Threat description
- MITRE ATT&CK technique
- Evidence
- Confidence level
- IOCs
- Recommended actions

---

## 🛡️ Agent Guardrails

Current guardrails include:

- Table allowlisting
- Field allowlisting
- Approved model allowlisting

Additional controls identified for future improvement:

- Time-window limits
- Row / payload limits
- PII redaction
- Audit logging
- Stronger validation
- Least-privilege API permissions

---

## 🚨 Endpoint Remediation(optional)

The project integrates with the Microsoft Defender for Endpoint API.

### Functions Added

```python
get_bearer_token()
```

Gets an Azure authentication token.

```python
get_mde_workstation_id_from_name()
```

Finds the Defender machine ID from a hostname.

```python
quarantine_virtual_machine()
```

Isolates a machine using the Microsoft Defender API.

Isolation is only offered when:

```text
Threat Confidence = High
AND
The threat is associated with a specific endpoint
```

A human analyst must approve the action.

---

## 🚧 Current Limitations

Future improvements include:

- Better API error handling
- Strict yes/no validation
- Persistent audit logs
- Device un-isolation workflow
- User account remediation
- NSG remediation
- Stronger data protection controls

---

## 🧰 Technologies

- Python
- KQL
- Microsoft Defender for Endpoint
- Microsoft Sentinel
- Azure
- REST APIs
- LLM Tool Calling
- JSON Schema
- MITRE ATT&CK
- Agentic AI

---

## 🎯 Key Takeaways

This project helped me understand how Agentic AI can support SOC operations by combining threat hunting, structured AI outputs, security telemetry, APIs, and remediation workflows.

The biggest lesson was:

> **The more authority an AI agent has, the stronger its security guardrails must be.**

Human approval remains essential before disruptive actions such as endpoint isolation.

---

## ⚠️ Disclaimer

This project is intended for educational, lab, and authorized security-testing environments only.

Do not isolate or modify systems without proper authorization.
