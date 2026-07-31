# Microsoft Sentinel output

ProxyWatch can send detection lifecycle events to Microsoft Sentinel through the
Azure Monitor Logs Ingestion API. The output uses a flat, typed record per
detection so the DCR can map directly to a custom Log Analytics table. Signals,
reasons, connections, and listeners are `dynamic` columns.

The sender uses lifecycle events in every output mode:

- `DetectionCreated` when a candidate first qualifies for its selected mode.
- `DetectionUpdated` when a mode-relevant change occurs.
- `DetectionResolved` when the candidate no longer qualifies for long enough to be considered gone.

`EntityId` is stable across role changes and is the recommended correlation
key. Uploads run outside the classifier loop, use the Azure SDK's retry policy,
and are split below the Logs Ingestion API's 1 MB request limit.

A complete three-record sample suitable for the Azure custom-table/DCR creation
workflow is available at
[`docs/samples/proxywatch-sentinel-events.json`](samples/proxywatch-sentinel-events.json).
It contains created, updated, and resolved events and populates every column.

## Configuration

The DCE endpoint, DCR immutable ID, and stream name are always required:

```sh
export PROXYWATCH_SENTINEL_DCE_ENDPOINT='https://proxywatch-dce.westus2-1.ingest.monitor.azure.com'
export PROXYWATCH_SENTINEL_DCR_ID='dcr-00000000000000000000000000000000'
export PROXYWATCH_SENTINEL_STREAM_NAME='Custom-ProxywatchDetections_CL'
export PROXYWATCH_SENTINEL_MODE='balanced'
```

The endpoint can also be a direct DCR logs-ingestion endpoint. Do not use the
DCR Azure resource ID for `PROXYWATCH_SENTINEL_DCR_ID`; use its `immutableId`
value, which starts with `dcr-`.

### Output modes

`PROXYWATCH_SENTINEL_MODE` controls event volume. It accepts either the name or
number below. When unset, the default is `balanced` (`2`).

| Value | Name | Behavior |
|---|---|---|
| `1` | `verbose` | Original behavior. Every candidate selected by ProxyWatch's normal score/control-role filter is created immediately. Exact changes to score/confidence bands, reasons, signals, connections, and listeners produce updates; disappearance resolves immediately. Use for troubleshooting and short collection windows. |
| `2` | `balanced` | Recommended default. Sends strong evidence, high-value signals, control roles, active tunneling, and scores of at least 80. Noncritical candidates must remain eligible for 5 seconds. Only meaningful security transitions generate updates, noncritical changes are coalesced for 15 seconds, and resolution requires 60 seconds of absence. |
| `3` | `strong_evidence` | Lowest-volume mode. Uses the balanced lifecycle and canonical payload, but only for candidates where ProxyWatch sets `StrongEvidence=true`. Strong-evidence creation is immediate. Aliases `strong-evidence`, `strong`, and `strong_only` are also accepted. |

Balanced mode generates an update only for role changes, entry to or exit from
`tunneling`, role escalation, newly strong evidence, control-channel endpoint
changes, traffic verification, upward score thresholds at 70/85/95, or a new
high-value signal. Confidence changes alone, reason wording, socket ordering,
TCP state, and local ephemeral ports do not trigger updates.

High-value signals currently include ProxyWatch's hard distinguishing signals
plus `beacon-interval-confirmed`, `pivot-anon-exec-memory`,
`pivot-non-loopback-internal`, `session-control-channel-persistent`,
`session-impersonation-token`, and `session-shell-spawn`. This ensures that a
decisive behavioral signal is sent immediately even when its score is below 80.

Balanced and strong-evidence modes canonicalize network evidence before upload:

- Connections are unique, sorted remote `protocol/address/port/scope` tuples;
  local ephemeral endpoints and TCP state are omitted.
- Connections are capped at 20, TCP/UDP listeners at 10 each, signals at 24,
  and reasons at 12 per record.
- Aggregate connection and listener counters remain present even when dynamic
  detail reaches a cap.

Mode selection does not change the DCR/table schema. The sample file populates
the complete schema; balanced records may omit volatile fields inside the
dynamic connection objects.

### Managed identity

Managed identity is the default authentication mode:

```sh
export PROXYWATCH_SENTINEL_AUTH='managed_identity'
```

No credential values are required for a system-assigned identity. To select a
user-assigned identity, also set its client ID:

```sh
export AZURE_CLIENT_ID='00000000-0000-0000-0000-000000000000'
```

### Application ID and secret

```sh
export PROXYWATCH_SENTINEL_AUTH='client_secret'
export AZURE_TENANT_ID='00000000-0000-0000-0000-000000000000'
export AZURE_CLIENT_ID='00000000-0000-0000-0000-000000000000'
export AZURE_CLIENT_SECRET='replace-with-secret'
```

These values can also be stored in the ProxyWatch keystore. The identity—either
the managed identity or service principal—must have the **Monitoring Metrics
Publisher** role on the DCR resource. Role propagation can take several minutes.

## DCR input stream

Create a custom table named `ProxywatchDetections_CL`, then use the following
input stream declaration in the DCR. The configured stream name must exactly
match the `Custom-ProxywatchDetections_CL` key.

```json
{
  "streamDeclarations": {
    "Custom-ProxywatchDetections_CL": {
      "columns": [
        { "name": "TimeGenerated", "type": "datetime" },
        { "name": "SchemaVersion", "type": "string" },
        { "name": "EventType", "type": "string" },
        { "name": "EntityId", "type": "string" },
        { "name": "DetectionId", "type": "string" },
        { "name": "Cycle", "type": "long" },
        { "name": "Host", "type": "string" },
        { "name": "ProcessId", "type": "long" },
        { "name": "ProcessName", "type": "string" },
        { "name": "ProcessPath", "type": "string" },
        { "name": "User", "type": "string" },
        { "name": "Role", "type": "string" },
        { "name": "RoleFamily", "type": "string" },
        { "name": "State", "type": "string" },
        { "name": "Score", "type": "long" },
        { "name": "Confidence", "type": "long" },
        { "name": "StrongEvidence", "type": "boolean" },
        { "name": "ActiveProxying", "type": "boolean" },
        { "name": "TrafficVerified", "type": "boolean" },
        { "name": "InboundTotal", "type": "long" },
        { "name": "OutboundTotal", "type": "long" },
        { "name": "OutboundExternal", "type": "long" },
        { "name": "OutboundInternal", "type": "long" },
        { "name": "OutboundLoopback", "type": "long" },
        { "name": "TcpListenerCount", "type": "long" },
        { "name": "UdpListenerCount", "type": "long" },
        { "name": "ControlDurationSeconds", "type": "long" },
        { "name": "ControlRemoteAddress", "type": "string" },
        { "name": "ControlRemotePort", "type": "long" },
        { "name": "Signals", "type": "dynamic" },
        { "name": "Reasons", "type": "dynamic" },
        { "name": "Connections", "type": "dynamic" },
        { "name": "TcpListeners", "type": "dynamic" },
        { "name": "UdpListeners", "type": "dynamic" }
      ]
    }
  }
}
```

Use `source` as the DCR transformation when the destination table has the same
schema. A typical data flow is:

```json
{
  "streams": ["Custom-ProxywatchDetections_CL"],
  "destinations": ["<log-analytics-destination-name>"],
  "transformKql": "source",
  "outputStream": "Custom-ProxywatchDetections_CL"
}
```

## Useful KQL

Current unresolved detections:

```kusto
ProxywatchDetections_CL
| summarize arg_max(TimeGenerated, *) by EntityId
| where EventType != "DetectionResolved"
| project TimeGenerated, Host, ProcessName, ProcessId, Role, State, Score, Signals
```

Pivot activity:

```kusto
ProxywatchDetections_CL
| where Role == "control-pivot" or set_has_element(Signals, "pivot-non-loopback-internal")
| project TimeGenerated, EventType, Host, ProcessName, ProcessId,
          ControlRemoteAddress, ControlRemotePort, Connections, Reasons
```
