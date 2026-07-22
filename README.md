# IDMEFv2 Internal Alert App for Splunk Enterprise Security

A Splunk Enterprise Security app that monitors finding lifecycle events, converts them to **IDMEFv2 V08** alerts, and delivers them to an external HTTP endpoint.

The app is lifecycle-aware: the first finding is sent as a new IDMEFv2 alert, while later status changes are sent as updates linked through `PredID`.

---

## Table of contents

- [Overview](#overview)
- [Main features](#main-features)
- [How it works](#how-it-works)
- [Minimum requirements](#minimum-requirements)
- [Installation](#installation)
- [Initial configuration](#initial-configuration)
- [Alert action parameters](#alert-action-parameters)
- [Scheduling](#scheduling)
- [Lifecycle mapping](#lifecycle-mapping)
- [IDMEFv2 lifecycle and update chaining](#idmefv2-lifecycle-and-update-chaining)
- [Category mapping](#category-mapping)
- [Delivery modes](#delivery-modes)
- [Monitoring and troubleshooting](#monitoring-and-troubleshooting)
- [State files](#state-files)
- [Security considerations](#security-considerations)
- [Known limitations](#known-limitations)
- [Project structure](#project-structure)
- [Recommended acceptance test](#recommended-acceptance-test)

---

## Overview

The app monitors two Splunk Enterprise Security sources:

- newly created findings from `index=notable`;
- lifecycle changes from `incident_review_lookup`.

For every new lifecycle event, the app:

1. reads the result produced by the scheduled search;
2. validates and deduplicates the event;
3. correlates it with its Splunk ES finding by `rule_id`;
4. optionally retrieves additional Mission Control and notable-event context;
5. maps the normalized event to an IDMEFv2 V08 JSON object;
6. validates the essential IDMEFv2 fields;
7. writes the payload locally or sends it through HTTP;
8. updates the local state only after successful processing.

---

## Main features

- Splunk ES finding creation and lifecycle monitoring.
- IDMEFv2 V08 payload generation.
- Semantic mapping of Splunk ES review states to IDMEFv2 `Incident`, `Open`, and `Closed` lifecycle messages.
- `PredID` chaining between updates of the same logical alert.
- Stable `StartTime` across the entire lifecycle.
- `EndTime` generation when an alert is closed.
- Deduplication based on `event_uid`.
- Static category mapping from Splunk correlation-search names to IDMEFv2 categories.
- Optional enrichment from Mission Control investigations and `index=notable`.
- HTTP delivery with:
  - no authentication;
  - Bearer authentication;
  - Basic username/password authentication.
- TLS certificate verification.
- Local dry-run mode with complete JSON output.
- Detailed HTTP success and failure logging.
- No third-party Python packages required.

---

## How it works

```text
Splunk ES detection
        |
        v
index=notable / incident_review_lookup
        |
        v
Scheduled search:
IDMEFv2 - Splunk ES Incident Review Changes
        |
        v
Custom alert action:
idmefv2_internal_alert_action
        |
        +--> lifecycle correlation
        +--> Mission Control lookup
        +--> notable enrichment
        +--> IDMEFv2 V08 mapping
        +--> static validation
        +--> deduplication and state update
        |
        v
Local JSON files or external HTTP endpoint
```

The packaged scheduled search is disabled by default and must be configured and enabled after installation.

---

## Minimum requirements

### Splunk

- Splunk Enterprise with Python 3 custom alert action support.
- Tested baseline: **Splunk Enterprise 9.4.x**.
- A compatible Splunk Enterprise Security installation that provides:
  - `index=notable`;
  - `incident_review_lookup`;
  - `reviewstatuses_lookup`.
- A Splunk account with permission to:
  - install applications;
  - edit and enable scheduled searches;
  - configure alert actions;
  - search the notable index;
  - read the required lookups.
- The Splunk service account must be able to write to:
  - `$SPLUNK_HOME/etc/apps/Splunk-ES-Connector/lookups`;
  - `$SPLUNK_HOME/var/log/splunk`.

Mission Control investigation enrichment is supported but is not mandatory. If no matching investigation is found, processing continues with the available notable and lifecycle data.

### Network and receiver

For HTTP delivery, the Splunk Search Head must have network access to the configured receiver.

The receiver must expose an HTTP endpoint that accepts JSON payloads through the `POST` method.

The message body contains the generated IDMEFv2 JSON object. The receiver does not require any connector-specific protocol support beyond the ability to accept JSON over HTTP.

The app sends:

```http
Content-Type: application/json
Accept: */*
```

The IDMEFv2 object is sent directly as the request body, without an additional wrapper.

Authentication is optional and depends on the receiver configuration. The app supports:

- no authentication;
- Basic username/password authentication;
- Bearer token authentication.

HTTPS is also optional.

When HTTPS is used, TLS certificate verification can be enabled or disabled through the alert action settings. Certificate verification should normally remain enabled for production endpoints and disabled only in controlled test environments when required.

### Deployment model

The current release is intended primarily for a standalone Search Head or another controlled single execution node.

In a Search Head Cluster, validate scheduling, lookup replication, and concurrent writes before production use, because lifecycle and deduplication state are stored in local CSV lookup files.

---

## Installation

### Option 1: build a Splunk package

Clone or download the repository, then run:

```bash
chmod +x package-app.sh
./package-app.sh ./release
```

The script creates:

```text
release/Splunk-ES-Connector-1.0.0.tar.gz
```

The packaging script excludes:

- `local/*`;
- Python cache files;
- Git metadata;
- previously generated packages.

This prevents local configuration and credentials from being included in the archive.

Install the package from Splunk Web:

1. Open **Apps**.
2. Select **Manage Apps**.
3. Select **Install app from file**.
4. Upload the generated `.tar.gz` archive.
5. Restart Splunk when requested.

### Option 2: manual installation

Copy the application directory to the Splunk apps directory:

```bash
cp -R Splunk-ES-Connector \
  "$SPLUNK_HOME/etc/apps/"
```

Set appropriate ownership:

```bash
chown -R splunk:splunk \
  "$SPLUNK_HOME/etc/apps/Splunk-ES-Connector"
```

Restart Splunk:

```bash
"$SPLUNK_HOME/bin/splunk" restart
```

Check the service:

```bash
"$SPLUNK_HOME/bin/splunk" status
```

---

## Initial configuration

The application includes the saved search:

```text
IDMEFv2 - Splunk ES Incident Review Changes
```

It is installed in a disabled state.

Configure it from:

```text
Settings
→ Searches, reports, and alerts
→ IDMEFv2 - Splunk ES Incident Review Changes
→ Edit
```

The saved search already includes the custom trigger action:

```text
Send IDMEFv2 Splunk ES alert
```

Before enabling it:

1. configure the target endpoint and authentication;
2. replace all `CHANGE-ME` organisation and entity values;
3. keep deduplication enabled;
4. choose local or HTTP delivery;
5. review the schedule and search window;
6. save the configuration;
7. enable the saved search.

A separate Splunk ES detection must create findings in `index=notable`. The connector does not replace the detection logic.

---

## Alert action parameters

| Parameter | Default | Description |
|---|---:|---|
| `enable_http_delivery` | `0` | `0` writes JSON locally; `1` sends it to `target_url`. |
| `target_url` | empty | Destination HTTP or HTTPS endpoint. Required for HTTP delivery. |
| `auth_type` | `none` | Supported values: `none`, `bearer`, `basic`. |
| `auth_token` | empty | Bearer token used when `auth_type=bearer`. |
| `auth_username` | empty | Username used when `auth_type=basic`. |
| `auth_password` | empty | Password used when `auth_type=basic`. |
| `verify_ssl` | `1` | Verifies the receiver certificate. Disable only in controlled test environments. |
| `timeout_seconds` | `30` | Timeout for internal REST calls and external HTTP delivery. |
| `enable_notable_enrichment` | `1` | Enables fallback enrichment searches against `index=notable`. |
| `notable_earliest` | `-365d` | Earliest time used by the optional notable enrichment search. |
| `minimum_notable_match_score` | `70` | Minimum score accepted by the fallback notable matching logic. |
| `dedup_enabled` | `1` | Skips lifecycle events already recorded in the processed-events store. |
| `debug_dump_payload` | `0` | Writes a redacted runtime action payload for troubleshooting. |
| `organisation_name` | `CHANGE-ME` | IDMEFv2 organisation name. |
| `organisation_id` | `CHANGE-ME` | IDMEFv2 organisation identifier. |
| `entity_name` | `CHANGE-ME` | IDMEFv2 entity name. |
| `entity_id` | `CHANGE-ME` | IDMEFv2 entity identifier. |
| `analyzer_name` | `Splunk ES` | IDMEFv2 analyzer name. |
| `analyzer_model` | `Splunk Enterprise Security` | IDMEFv2 analyzer model. |
| `analyzer_hostname` | empty | Optional hostname of the Splunk analyzer. |

Example configuration:

```text
Enable HTTP delivery:      1
Target URL:                https://receiver.example.org/topics/alerts
Auth Type:                 Basic username/password
Basic Auth Username:       connector-user
Basic Auth Password:       ********
Verify SSL:                1
Timeout seconds:           30
Enable deduplication:      1
Enable notable enrichment: 1

Organisation Name:         Example Organisation
Organisation ID:           ORG-001
Entity Name:               Example Entity
Entity ID:                 ENTITY-001

Analyzer Name:             Splunk ES
Analyzer Model:            Splunk Enterprise Security
Analyzer Hostname:         splunk-search-head
```

Do not commit real credentials to the repository.

---

## Scheduling

The packaged connector search uses:

```cron
*/5 * * * *
```

and a ten-minute search window:

```text
Earliest: -10m
Latest:   now
```

This overlap is intentional. Deduplication prevents an already processed lifecycle event from being sent again.

For faster tests, a two-minute schedule may be used:

```cron
1-59/2 * * * *
```

When testing with a separate detection that also runs every two minutes, stagger them:

```text
Detection: */2 * * * *
Connector: 1-59/2 * * * *
```

This allows the detection to create the finding before the connector reads it.

For production, choose a cadence appropriate for the Search Head load and required delivery latency.

---

## Lifecycle mapping

The app maps common Splunk ES review states to IDMEFv2 statuses:

| Splunk status code | Splunk label | IDMEFv2 `Status` |
|---:|---|---|
| `0` | Unassigned | `Incident` |
| `1` | New | `Incident` |
| `2` | In Progress | `Open` |
| `3` | Pending | `Open` |
| `4` | Resolved | `Closed` |
| `5` | Closed | `Closed` |

Unknown states fall back to:

```json
"Status": ["Incident"]
```

The original Splunk status is also preserved in the message `Note`.

---

## IDMEFv2 lifecycle and update chaining

Each lifecycle event emitted by the connector is represented by a new IDMEFv2 message with its own UUID in the `ID` field.

The IDMEFv2 status is determined by the lifecycle mapping described in the previous section.

Messages belonging to the same Splunk finding are linked through `PredID`. Each new message references the immediately preceding IDMEFv2 message and supersedes it.

The first message in a lifecycle does not contain `PredID`.

### Example lifecycle

A typical Splunk lifecycle:

```text
New → In Progress → Closed
```

is represented in IDMEFv2 as:

```text
Incident → Open → Closed
```

### Initial finding

A newly created Splunk finding in the `New` state is emitted as an
IDMEFv2 `Incident`.

Because this is the first message in the chain, it does not contain
`PredID`.

```json
{
  "ID": "11111111-1111-4111-8111-111111111111",
  "Status": [
    "Incident"
  ]
}
```

### Finding under investigation

When the Splunk finding changes to `In Progress`, the connector emits a
new message with:

- a new UUID in `ID`;
- `Status` set to `Open`;
- `PredID` pointing to the initial `Incident` message.

```json
{
  "ID": "22222222-2222-4222-8222-222222222222",
  "PredID": [
    "11111111-1111-4111-8111-111111111111"
  ],
  "Status": [
    "Open"
  ]
}
```

The message referenced by `PredID` is considered obsolete and should no
longer be treated as the current representation of the finding.

### Closed finding

When the Splunk finding changes to `Resolved` or `Closed`, the connector
emits another message with:

- a new UUID in `ID`;
- `Status` set to `Closed`;
- `PredID` pointing to the immediately preceding message;
- `EndTime` containing the lifecycle closing timestamp.

```json
{
  "ID": "33333333-3333-4333-8333-333333333333",
  "PredID": [
    "22222222-2222-4222-8222-222222222222"
  ],
  "Status": [
    "Closed"
  ],
  "EndTime": "2026-07-17T15:30:00Z"
}
```

### Timestamp behavior

- `CreateTime`
  - for the first message: the original Splunk finding creation time;
  - for lifecycle updates: the timestamp of the corresponding Splunk
    status change.

- `StartTime`
  - represents the deduced start of the underlying event;
  - remains unchanged throughout the complete lifecycle.

- `ReportTime`
  - represents the time at which the connector generated and reported
    the current IDMEFv2 message;
  - is generated in UTC.

- `EndTime`
  - is omitted while the finding is active;
  - is added when the resulting IDMEFv2 status is `Closed`.

### State update rules

The connector updates its local lifecycle state only after the message
has been processed successfully.

A message is considered successfully processed when either:

- it has been written successfully in local delivery mode; or
- the external HTTP receiver has returned a successful `2xx` response.

If delivery fails, the lifecycle state is not advanced. This allows the
same Splunk lifecycle event to be retried without incorrectly creating a
new predecessor chain.

---

## Category mapping

The app maps Splunk ES correlation-search names to IDMEFv2 V08 categories through:

```text
lookups/idmefv2_category_mapping.csv
```

The mapping is matched against fields such as:

- `search_name`;
- `rule_name`;
- `rule_title`.

Matching is case-insensitive and whitespace-normalized.

When no approved mapping is found, the app uses:

```json
"Category": ["Other.Undetermined"]
```

Additional Splunk and MITRE ATT&CK category information may be preserved in:

```text
ext-Category
AltCategory
```

Administrators may extend the CSV mapping file, but should preserve its existing columns and avoid editing it while the application is being upgraded.

---

## Delivery modes

### Local dry-run mode

Set:

```text
enable_http_delivery = 0
```

The app writes:

```text
$SPLUNK_HOME/var/log/splunk/idmefv2_generated_payload_latest.json
$SPLUNK_HOME/var/log/splunk/idmefv2_generated_payload_<event_uid>.json
$SPLUNK_HOME/var/log/splunk/idmefv2_generated_payloads.json
```

The history file is a JSON array containing metadata and complete payloads.

Local mode is recommended for initial mapping and lifecycle tests.

### HTTP delivery mode

Set:

```text
enable_http_delivery = 1
```

The app sends the IDMEFv2 object directly through HTTP `POST`.

A response with status code `2xx` is considered successful. Other status codes are logged with their response body.

Supported authentication modes:

```text
none
bearer
basic
```

Example successful log:

```text
IDMEFv2 payload sent successfully.
status_code=200
```

Example gateway response:

```json
{
  "offsets": [
    {
      "partition": 0,
      "offset": 4810,
      "error_code": null,
      "error": null
    }
  ]
}
```

In the current release, successful HTTP payloads are not automatically copied to the local JSON history. Use local mode for payload inspection, or retrieve the accepted record from the receiving system.

---

## Monitoring and troubleshooting

### Application log

The main log is:

```text
$SPLUNK_HOME/var/log/splunk/idmefv2_internal_alert_app.log
```

Monitor delivery activity:

```bash
LOG="$SPLUNK_HOME/var/log/splunk/idmefv2_internal_alert_app.log"

tail -n 0 -F "$LOG" \
| grep --line-buffered -Ei \
'Sending IDMEFv2 payload|IDMEFv2 payload sent successfully|IDMEFv2 payload delivery failed|Failed to send IDMEFv2 payload|exception_type=|status_code=|response=|Alert action complete'
```

Successful run:

```text
sent=1 skipped=0 failed=0
```

Run with no new lifecycle events:

```text
sent=0 skipped=1 failed=0
```

Failed delivery:

```text
sent=0 skipped=0 failed=1
```

### Saved-search activity

Run this SPL search in Splunk:

```spl
index=_internal source=*scheduler.log
savedsearch_name="IDMEFv2 - Splunk ES Incident Review Changes"
earliest=-30m
| table _time status result_count run_time sid savedsearch_name
| sort - _time
```

Interpretation:

- `status=success`, `result_count=0`: the connector ran but found nothing new;
- `status=success`, `result_count>0`: lifecycle rows were passed to the action;
- `status=failed`: the scheduled search itself failed.

### Common HTTP errors

| Error | Meaning |
|---|---|
| `401` | Missing or rejected authentication. |
| `403` | Authenticated user is not authorized. |
| `404` | Incorrect endpoint path. |
| `405` | The endpoint does not accept `POST`. |
| `406` | The receiver rejected the HTTP content negotiation. Verify `Accept: */*`. |
| `400` / `422` | The receiver rejected the JSON body or IDMEFv2 content. |
| `500` / `502` / `503` | Receiver or reverse-proxy failure. |
| certificate verification error | The server certificate or CA is not trusted. |
| connection refused | Nothing is listening on the destination port. |
| timeout | Routing, firewall, proxy, or receiver availability problem. |

### Validate Python syntax

```bash
APP="$SPLUNK_HOME/etc/apps/Splunk-ES-Connector"

"$SPLUNK_HOME/bin/splunk" cmd python3 -m py_compile \
  "$APP/bin/sender.py" \
  "$APP/bin/splunk_rest_client.py" \
  "$APP/bin/idmefv2_internal_alert_action.py"
```

No output means that the files compiled successfully.

### Check the effective saved-search configuration

```bash
"$SPLUNK_HOME/bin/splunk" btool savedsearches list \
  "IDMEFv2 - Splunk ES Incident Review Changes" \
  --app=Splunk-ES-Connector \
  --debug
```

Be careful: `btool` output may contain configured credentials. Do not paste unredacted output into tickets, chats, or public repositories.

---

## State files

### Processed lifecycle events

```text
lookups/idmefv2_processed_events.csv
```

Purpose:

- records successfully processed `event_uid` values;
- prevents repeated delivery when search windows overlap.

Columns:

```text
event_uid,rule_id,status,review_epoch,processed_at,result
```

### Alert chain state

```text
lookups/idmefv2_alert_state.csv
```

Purpose:

- stores the latest emitted IDMEFv2 `ID` for each logical Splunk finding;
- preserves the original `StartTime`;
- supplies the `PredID` for the next lifecycle update.

Columns:

```text
correlation_key,last_id,last_event_uid,last_status,last_review_epoch,start_time,created_at,updated_at
```

### Operational rules

- **Do not** edit state files while the alert action is running.
- Back up state files before resetting a test environment.
- **Do not** reset alert-chain state for a finding whose lifecycle will continue, unless a new independent chain is intended.
- Deduplication should remain enabled in normal operation.

---

## Security considerations

- Keep `verify_ssl=1` in production.
- Use `verify_ssl=0` only for isolated test environments.
- Restrict access to `local/savedsearches.conf`, because it may contain endpoint credentials.
- Never commit the `local` directory to source control.
- The packaging script excludes `local/*`.
- Prefer a dedicated receiver account with only the permissions required to publish alerts.
- Rotate credentials according to the organisation security policy.
- `debug_dump_payload` redacts known authentication secrets and the Splunk session key, but the dump may still contain sensitive alert data.
- Enable debug payload dumping only during controlled troubleshooting.

---

## Known limitations

- Validation is currently static and does not perform full validation against the complete IDMEFv2 V08 JSON Schema.
- Any HTTP `2xx` response is treated as successful; receiver-specific response semantics are not interpreted.
- Successful HTTP payloads are not automatically archived in the local JSON history.
- `Source.ID` and `Target.ID` are generated independently for each message.
- CSV state storage requires additional validation before use with concurrent execution across multiple Search Head Cluster members.
- Investigation enrichment is best-effort and may be empty without blocking delivery.

---

## Project structure

| Path | Responsibility |
|---|---|
| `bin/idmefv2_internal_alert_action.py` | Main custom alert action entry point and processing pipeline. |
| `bin/action_payload.py` | Reads Splunk action input and extracts result rows. |
| `bin/config_loader.py` | Parses alert action configuration. |
| `bin/mission_control_client.py` | Retrieves Mission Control investigations. |
| `bin/incident_review_service.py` | Reads lifecycle history and status labels. |
| `bin/notable_search_service.py` | Performs optional notable-event enrichment. |
| `bin/normalizer.py` | Builds the internal normalized alert context. |
| `bin/idmefv2_mapper.py` | Maps normalized data to IDMEFv2 V08. |
| `bin/idmefv2_validator.py` | Performs essential static validation. |
| `bin/idmefv2_category_mapping.py` | Loads and applies category mappings. |
| `bin/splunk_rest_client.py` | Calls local Splunk APIs and external HTTP endpoints. |
| `bin/sender.py` | Sends IDMEFv2 payloads or writes local JSON files. |
| `bin/state_store.py` | Deduplicates processed lifecycle events. |
| `bin/alert_state_store.py` | Stores the latest ID and stable start time for each chain. |
| `bin/logging_utils.py` | Configures the application log. |
| `default/alert_actions.conf` | Custom alert action definition and defaults. |
| `default/savedsearches.conf` | Packaged lifecycle-monitoring saved search. |
| `default/data/ui/alerts/` | Splunk Web form for alert action settings. |
| `lookups/idmefv2_category_mapping.csv` | Splunk search-name to IDMEFv2 category mapping. |
| `lookups/idmefv2_processed_events.csv` | Deduplication state. |
| `lookups/idmefv2_alert_state.csv` | IDMEFv2 lifecycle-chain state. |
| `package-app.sh` | Creates the Splunk-installable package. |

---

## Recommended acceptance test

Before production use, verify one complete lifecycle:

```text
New → In Progress → Closed
```

Expected result:

1. `Incident`
   - represents the initial Splunk `New` finding;
   - has no `PredID`;
2. `Open`
   - represents the Splunk `In Progress` finding;
   - `PredID` contains the initial `Incident` message ID;
3. `Closed`
   - represents the Splunk `Resolved` or `Closed` finding;
   - `PredID` contains the preceding `Open` message ID;
   - `EndTime` is present;
4. another connector run with no new lifecycle event
   - sends no duplicate message;
5. receiver confirms successful ingestion of every expected IDMEFv2 message.

The application log should finish each successful action with:

```text
failed=0
```
