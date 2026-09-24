# Threat Hunting and Telemetry Analysis Using Wazuh SIEM Dashboard Filters

**Target Environment:** Wazuh SIEM (`192.168.6.133`)

**Monitored Agents:** `Windows_11` (Agent 002) & `Wazuh-Server` (Agent 000 / Manager)

**Date of Execution:** September 24, 2026

---

## 1. Objective

The objective of this lab is to utilize the filtering, query (DQL), and search features in the **Wazuh Dashboard** to isolate, analyze, and document security telemetry from specific agents (`Windows_11` and `Wazuh-Server`). The lab demonstrates how to narrow down telemetry using time range controls, Rule Level severity filters, and event channel categories (Security, Application, System, and Provider Name).

---

## 2. Methodology & Step-by-Step Dashboard Filtering

### Step 1: Navigating to Overview and Threat Hunting

1. Log into the Wazuh Manager web dashboard (`https://192.168.6.133`).
2. From the main menu, navigate to **Threat Intelligence** and select **Threat Hunting**.

![Figure 1: Navigating to Threat Hunting in the Wazuh UI](screenshots/Screenshot%20From%202026-09-24%2011-26-21.png)
*Figure 1: Accessing Threat Hunting from the navigation menu.*

---

### Step 2: Global Overview & Top Agent Distribution

1. In the **Threat Hunting Dashboard**, observe the global alert statistics.
2. Review the **Top 5 agents** chart to identify active hosts generating security events (`Windows_11` and `Wazuh-Server`).

| Summary Metric | Value Observed |
| :--- | :--- |
| **Total Alerts** | 78 events |
| **Medium Severity (Level 7-11)** | 21 events |
| **Low Severity (Level 0-6)** | 56 events |
| **Authentication Success** | 3 events |

![Figure 2: Threat Hunting Dashboard and Agent Distribution](screenshots/Screenshot%20From%202026-09-24%2011-27-04.png)
*Figure 2: Alert distribution showing activity across Windows_11 and Wazuh-Server.*

---

### Step 3: Filtering by Time Range

1. Click on the time picker in the top right corner of the dashboard.
2. Adjust the time window to **Last 24 hours** to view broader activity patterns.
3. For real-time investigation, adjust the time window to **Last 15 minutes** to capture immediate log bursts.

![Figure 3: Time Filter Set to Last 15 Minutes](screenshots/Screenshot%20From%202026-09-24%2011-40-13.png)
*Figure 3: Filtering log ingestion over a 15-minute window.*

---

### Step 4: Filtering by Rule Level Severity

To isolate specific threat levels, apply a rule level filter using the filter bar:

1. Click **+ Add filter**.
2. Select Field: `rule.level`, Operator: `is`, Value: `3`.
3. Review events assigned to low severity (Level 3) across agents.

![Figure 4: Active Filter applied for rule.level = 3](screenshots/Screenshot%20From%202026-09-24%2011-30-44.png)
*Figure 4: Ingested events filtered specifically by Rule Level 3 (30 hits).*

![Figure 5: Event Stream View for Rule Level 3 Alerts](screenshots/Screenshot%20From%202026-09-24%2011-31-07.png)
*Figure 5: Events table displaying Apparmor, PAM login, and 7-Zip vulnerability updates.*

---

### Step 5: Filtering by Windows Event Channel Categories

To analyze events from the Windows endpoint (`Windows_11`), filter by event channel categories:

#### A. Filtering by Security Channel (`data.win.system.channel: Security`)

1. Add filter: `data.win.system.channel` is `Security`.
2. Result: 6 hits recorded.
3. Events isolated include:
   - **Rule 60104:** Windows audit failure event (Level 5)
   - **Rule 67023:** Non service account logged off (Level 3)
   - **Rule 67028:** Special privileges assigned to new logon (Level 3)
   - **Rule 60118:** Windows Workstation Logon Success (Level 3)

![Figure 6: Filtering Events by Security Channel](screenshots/Screenshot%20From%202026-09-24%2011-36-15.png)
*Figure 6: Filtering Windows Security channel logs returning 6 hits.*

![Figure 7: Security Events Table Detail](screenshots/Screenshot%20From%202026-09-24%2011-36-26.png)
*Figure 7: Expanded log table showing Logon Success and Audit Failure events on Windows_11.*

#### B. Filtering by Application Channel (`data.win.system.channel: Application`)

1. Change channel filter to: `data.win.system.channel` is `Application`.
2. Result: 28 hits recorded.
3. Events isolated include:
   - **Rule 60642:** Software protection service scheduled successfully (Level 3)
   - **Rule 60608:** Summary event of the report's signatures (Level 4)

![Figure 8: Filtering Events by Application Channel](screenshots/Screenshot%20From%202026-09-24%2011-36-49.png)
*Figure 8: Histogram displaying 28 events in the Application channel.*

![Figure 9: Application Channel Logs Table](screenshots/Screenshot%20From%202026-09-24%2011-37-08.png)
*Figure 9: Summary events and scheduled task logs isolated from agent Windows_11.*

#### C. Filtering by System Channel (`data.win.system.channel: System`)

1. Change channel filter to: `data.win.system.channel` is `System`.
2. Result: 5 hits recorded.
3. Events isolated include:
   - **Rule 61104:** Service startup type was changed (Level 3)
   - **Rule 61102:** Windows System error event (Level 5)

![Figure 10: Filtering Events by System Channel](screenshots/Screenshot%20From%202026-09-24%2011-37-31.png)
*Figure 10: Ingested system events for service configuration changes.*

---

### Step 6: Advanced DQL Search (Provider Name Search)

To search for events originating from specific Windows subsystem providers, use **Dashboards Query Language (DQL)**:

Query Syntax:

```text
data.win.system.providerName: "Microsoft-Windows-Security-Auditing"
```

![Figure 11: DQL Query for Microsoft-Windows-Security-Auditing](screenshots/Screenshot%20From%202026-09-24%2011-43-38.png)
*Figure 11: Executing DQL query to capture security auditing telemetry.*

---

## 3. Telemetry Filtering Summary Table

| Filter Parameter | Field Query / Filter Applied | Hits Captured | Agent Identified | Primary Rules Triggered |
|---|---|---|---|---|
| All Events (24h) | None (Global View) | 78 | Windows_11, Wazuh-Server | 503, 533, 60118, 60122 |
| Rule Severity | `rule.level: 3` | 30 | Wazuh-Server, Windows_11 | 52000, 52002, 23502, 5402 |
| Security Channel | `data.win.system.channel: Security` | 6 | Windows_11 | 60104, 67023, 67028, 60118 |
| Application Channel | `data.win.system.channel: Application` | 28 | Windows_11 | 60642, 60608 |
| System Channel | `data.win.system.channel: System` | 5 | Windows_11 | 61104, 61102 |
| Provider Search | `data.win.system.providerName: "Microsoft-Windows-Security-Auditing"` | 6 | Windows_11 | 60104, 67023, 67028, 60118 |

---

## 4. Operational Impact & Conclusion

1. **Precision Telemetry Isolation:** Utilizing custom filters (Rule Level, Event Channel, and DQL Queries) allows SOC analysts to quickly eliminate noisy baseline events and isolate critical endpoint logs.
2. **Agent Attribution Confirmed:** Specific channels (Security, Application, System) verified that log streams were correctly attributed to the endpoint agent Windows_11.
3. **Investigation Workflow Validated:** Combining time-range selectors with search fields provides an efficient method for threat hunting and incident triage in Wazuh SIEM.
