# Detection Rules Reference

LogSentinel ships with 7 detection rules covering common attack patterns. Rules are defined in `config/rules.yaml` and can be customized without code changes.

## Rule Types

### Threshold Rules
Count events matching criteria within a time window. Used for brute force and scanning detection.

### Pattern Rules
Match regex patterns against specific event fields. Used for web attack detection (SQLi, XSS, path traversal).

### Correlation Rules
Correlate related events across time. Used for privilege escalation detection (failure followed by success).

## Rule Reference

### DET-001: SSH Brute Force

| Field | Value |
|-------|-------|
| **Attack** | SSH Brute Force |
| **Severity** | High |
| **Log Source** | auth.log |
| **Type** | Threshold |
| **Threshold** | 5 failed logins |
| **Time Window** | 60 seconds |
| **MITRE ATT&CK** | T1110 — Brute Force |

**Description:** Detects multiple failed SSH login attempts from the same IP address within a 60-second window.

**Response:** Review the source IP, check for additional indicators of compromise, block if malicious.

### DET-002: Port Scan

| Field | Value |
|-------|-------|
| **Attack** | Port Scan |
| **Severity** | Medium |
| **Log Source** | auth.log, syslog |
| **Type** | Threshold |
| **Threshold** | 10 unique ports |
| **Time Window** | 60 seconds |
| **MITRE ATT&CK** | T1046 — Network Service Scanning |

**Description:** Detects connection attempts to multiple ports from a single IP address, indicating reconnaissance.

**Response:** Investigate the source IP, determine if scanning is authorized (e.g., vulnerability assessment).

### DET-003: SQL Injection

| Field | Value |
|-------|-------|
| **Attack** | SQL Injection (SQLi) |
| **Severity** | High (Critical with 200 response) |
| **Log Source** | access.log |
| **Type** | Pattern |
| **Pattern** | `(?i)(\%27|\%22|\'|\"|\-\-|UNION|SELECT|INSERT|DROP|OR\s+\d+\s*\=)` |
| **MITRE ATT&CK** | T1190 — Exploit Public-Facing Application |

**Description:** Detects SQL injection attempts in HTTP request parameters including UNION-based, error-based, and boolean-based injection patterns.

**Escalation:** Severity escalates to **Critical** if the SQLi attempt receives a successful HTTP response (200, 201, 302).

**Response:** Review web server logs for successful SQLi attempts, check database for unauthorized access.

### DET-004: XSS Attack

| Field | Value |
|-------|-------|
| **Attack** | Cross-Site Scripting (XSS) |
| **Severity** | Medium (Critical with 200 response) |
| **Log Source** | access.log |
| **Type** | Pattern |
| **Pattern** | `(?i)(<script|alert\(|onerror=|onload=|onclick=|javascript:)` |
| **MITRE ATT&CK** | T1059.007 — Command and Scripting Interpreter |

**Description:** Detects reflected/stored XSS payloads in HTTP requests including script tags, event handlers, and javascript: URIs.

**Escalation:** Severity escalates to **Critical** if the XSS payload receives a successful HTTP response.

**Response:** Investigate if XSS was successful, implement input sanitization, review WAF rules.

### DET-005: Privilege Escalation

| Field | Value |
|-------|-------|
| **Attack** | Privilege Escalation |
| **Severity** | Critical |
| **Log Source** | auth.log |
| **Type** | Correlation |
| **Time Window** | 300 seconds (5 minutes) |
| **MITRE ATT&CK** | T1068 — Exploitation for Privilege Escalation |

**Description:** Correlates failed sudo attempts followed by a successful sudo from the same user within 5 minutes. This pattern suggests an attacker who initially lacked privileges but escalated.

**Response:** Immediately investigate the user account, check for unauthorized access, review all commands executed during the session.

### DET-006: Directory Traversal

| Field | Value |
|-------|-------|
| **Attack** | Directory Traversal |
| **Severity** | Medium |
| **Log Source** | access.log |
| **Type** | Pattern |
| **Pattern** | `(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\\)` |
| **MITRE ATT&CK** | T1190 — Exploit Public-Facing Application |

**Description:** Detects directory traversal attempts using ../ patterns in URL paths, including URL-encoded variants.

**Response:** Review file system for unauthorized access, patch the vulnerable endpoint.

### DET-007: User Enumeration

| Field | Value |
|-------|-------|
| **Attack** | User Enumeration |
| **Severity** | Medium |
| **Log Source** | auth.log |
| **Type** | Threshold (unique users) |
| **Threshold** | 3 unique usernames |
| **Time Window** | 60 seconds |
| **MITRE ATT&CK** | T1589.001 — Gather Victim Identity Information |

**Description:** Detects attempts to enumerate valid usernames by observing multiple invalid user login attempts from the same IP.

**Response:** Rate-limit authentication attempts, monitor for additional enumeration patterns.

## Customizing Rules

Edit `config/rules.yaml` to adjust:

- **Thresholds**: Change `threshold` values to reduce/increase sensitivity
- **Time windows**: Adjust `time_window_seconds` to change detection duration
- **Severity**: Modify `severity` levels to match your organization's classification
- **Patterns**: Update regex patterns to detect new attack variations
- **Recommendations**: Customize response actions for each alert type

Example — lower brute force threshold:

```yaml
- rule_id: "DET-001"
  title: "SSH Brute Force Attack"
  severity: "High"
  conditions:
    event_type: "failed_login"
    threshold: 3  # Changed from 5 to 3
    time_window_seconds: 30  # Changed from 60 to 30
```
