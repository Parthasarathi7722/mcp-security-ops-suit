# Playbook 03: Threat Hunting

> Proactive threat hunting workflow using AI to translate TTPs into queries, run hunts, and enrich findings.

## MCP Servers Required

| Server | Purpose | Required |
|---|---|---|
| `security-detections` | Sigma/ESCU/KQL rule database | Yes |
| `sentinel` or `splunk` | Execute hunt queries | Yes |
| `greynoise` | IP enrichment for hunt results | Recommended |
| `opencti` | Threat actor context, IOC feeds | Recommended |
| `virustotal` | Hash/URL verification | Optional |
| `jira` | Document hunt findings | Optional |

## Trigger

Proactive — scheduled hunts, new threat intelligence, or analyst hypothesis.

## Workflow

### Hunt Type 1: TTP-Based Hunt

**Prompt:**
```
I want to hunt for [MITRE ATT&CK TECHNIQUE] (e.g., T1059.001 — PowerShell execution)
in our environment.

1. Check Security Detections for Sigma rules matching this technique
2. Translate the best matching rule to KQL for Sentinel
3. Run the query against the last 30 days of logs
4. For any hits, enrich source IPs via GreyNoise
5. Summarise findings with risk assessment
```

### Hunt Type 2: IOC-Based Hunt

**Prompt:**
```
We received new IOCs from a threat advisory:
- IPs: [list]
- Domains: [list]
- Hashes: [list]

1. Check OpenCTI for context — which threat actor, campaign, and TTPs?
2. Run Sentinel queries to check if any of these IOCs appear in our logs
   (network, DNS, endpoint, proxy)
3. For any matches, pull the full event context — user, machine, timestamp
4. Check GreyNoise for IP reputation on any matching IPs
5. Generate a findings report
```

### Hunt Type 3: Anomaly-Based Hunt

**Prompt:**
```
Hunt for anomalous [activity type] (e.g., "outbound data transfers > 500MB
to new external IPs") in the last 14 days.

1. Build a KQL/SPL query for the anomaly pattern
2. Run the query
3. Baseline: What's normal volume for this activity?
4. Flag anything > 2 standard deviations above baseline
5. Enrich flagged IPs/domains via GreyNoise and OpenCTI
6. Classify each finding: True Positive / Benign / Needs Investigation
```

## Hunt Hypothesis Template

```
HYPOTHESIS: [Threat actor / TTP] may be present in our environment because
[reason — new intel, similar industry targeting, vulnerability exposure].

DATA SOURCES: [Which logs to query — endpoint, network, identity, cloud]

DETECTION LOGIC: [What pattern to search for]

SUCCESS CRITERIA: [What constitutes a finding vs. false positive]

TIME RANGE: [How far back to search]
```

## Example Session

```
Analyst: "New advisory from CISA about Volt Typhoon targeting critical
          infrastructure via living-off-the-land techniques. Run a hunt
          for T1059.001 (PowerShell), T1053.005 (Scheduled Tasks), and
          T1003.001 (LSASS dumping) across the last 90 days."

AI: [Queries Security Detections]
    → Found 12 Sigma rules across all three techniques
    → Translating top rules to KQL...

    [Runs Sentinel queries]
    → T1059.001: 847 events (mostly legitimate admin scripts)
    → T1053.005: 23 new scheduled tasks created
    → T1003.001: 2 hits — procdump.exe accessing lsass.exe

    [Enriches via GreyNoise]
    → No outbound connections to known malicious IPs from affected hosts

    [Checks OpenCTI]
    → Volt Typhoon TTPs: matches our T1053.005 pattern — creates tasks
      named "WindowsUpdate" or "SystemCheck"
    → 1 of 23 scheduled tasks matches: "SystemHealthCheck" on SRV-DB-02

    FINDINGS:
    🔴 HIGH — SRV-DB-02: Scheduled task "SystemHealthCheck" matches
       Volt Typhoon naming pattern. Created 2026-01-03 by local admin.
       Runs encoded PowerShell every 4 hours. Needs immediate investigation.

    🟡 MEDIUM — 2 LSASS access events via procdump.exe on DEV-WS-15
       and DEV-WS-22. Possibly legitimate debugging but needs verification.

    🟢 LOW — Remaining PowerShell and task events appear legitimate.

    Shall I create a Jira investigation ticket for the HIGH finding
    and post to #threat-hunting?
```
