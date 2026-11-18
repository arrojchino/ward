# Unified Local SOC Toolkit (`toolkit.py`)

A read-only, local-only SOC utility CLI built with the Python standard library
only (tested on Python 3.14.9, Windows 11). It consolidates five focused
workflows: EML evidence triage, established-connection viewing, firewall-rule
viewing, scanner findings normalization, and tool-trace consistency checking.

All heuristics are **indicators, not verdicts**. No command in this toolkit
makes an authenticity, maliciousness, or causation claim.

## Safety model

- **Read-only.** No command opens an outbound socket, scans a remote host,
  modifies a firewall rule, writes registry/system state, or handles
  credentials.
- **No execution of untrusted content.** EML files are parsed as data only;
  attachments are never written to disk or executed, and URLs are never
  opened. Tool traces are never replayed or executed.
- **Local only.** The `connections` and `firewall-rules` commands read local
  operating-system state through read-only tools (`netstat -ano`,
  `Get-NetFirewallRule`) or from local files supplied with `--input`.
- **Stdlib only.** No third-party packages are required.

## Requirements

- Python 3.8+ (developed against 3.14.9).
- Windows for the live `connections` / `firewall-rules` sources. On other
  platforms, use `--input` with a local file.

## Usage

Show global help and each command's help:

```bash
python toolkit.py --help
python toolkit.py analyze-eml --help
python toolkit.py connections --help
python toolkit.py firewall-rules --help
python toolkit.py normalize-findings --help
python toolkit.py verify-trace --help
```

### 1. analyze-eml FILE

Parse an EML with `email.parser`, SHA-256 the raw bytes, list the evidence
headers (`From`, `To`, `Subject`, `Date`, `Received`,
`Authentication-Results`) and attachment names, and emit heuristic flags.
Output is JSON.

```bash
python toolkit.py analyze-eml sample/sample.eml
```

Heuristics emitted (all labeled `kind: "heuristic"`):

- `multiple_received_hops` - more than one `Received` hop.
- `sender_domain_mismatch` - `From` domain differs from `Reply-To`,
  `Return-Path`, or `Sender` domains.
- `suspicious_attachment_extension` - attachment extension commonly
  associated with executable content.

SPF/DKIM/DMARC values are reported *from the headers* and are not
independently verified.

### 2. connections

Read established TCP connections via `netstat -ano -p TCP` (parsed, never
sockets opened) or from a JSON file with `--input`. Remote-address scope is a
heuristic. Output a table by default, JSON with `--json`.

```bash
python toolkit.py connections
python toolkit.py connections --json
python toolkit.py connections --input sample/connections.json --json
```

`--input` accepts a list of objects (or `{"connections": [...]}`) with keys
such as `proto`, `local_address`, `remote_address`, `state`, and `pid`.

### 3. firewall-rules

Read Windows firewall rules via PowerShell `Get-NetFirewallRule` (name,
direction, action, enabled) or from a CSV with `--input`. This command only
reads; it never creates, changes, or deletes a rule.

```bash
python toolkit.py firewall-rules
python toolkit.py firewall-rules --json
python toolkit.py firewall-rules --input sample/firewall.csv
```

`--input` CSV may use columns `Name`/`DisplayName`, `Direction`, `Action`,
`Enabled` (case-insensitive).

### 4. normalize-findings CSV

Normalize a scanner findings CSV into the canonical schema, accepting common
header variants (for example `app_name`, `application_id`, `custom_severity`,
`cve`, `cwe_id`, `flaw_name`, `first_found_date`, `filename`, `status`,
`resolution_date`, `team`, `scan_type`). `Days to Resolve` is auto-calculated
from first-found and fixed dates when both parse. Prints counts by severity.

Canonical columns:

```
Application Name, Application ID, Custom Severity Name, CVE ID, CWE ID,
Flaw Name, First Found Date, Filename/Class, Finding Status, Fixed Date,
Team Name, Days to Resolve, Scan Type
```

```bash
python toolkit.py normalize-findings sample/findings.csv --out sample/normalized.csv
python toolkit.py normalize-findings sample/findings.csv --format json --out sample/normalized.json
python toolkit.py normalize-findings sample/findings.csv
```

### 5. verify-trace FILE

Read a JSON tool trace and heuristically check that required evidence fields
are present and that the record hash (`record_sha256`, SHA-256 of the
canonical JSON of `record`) is consistent. Modeled on `redline`'s rule that
hash/verdict recomputation checks *record consistency, not authenticity*.
No captured content is executed and no remote target is contacted.

```bash
python toolkit.py verify-trace sample/trace.json
```

Status values: `consistent_evidence_heuristic`,
`inconsistent_record_hash_heuristic`, and
`incomplete_or_unverifiable_evidence_heuristic`.

## Sample fixtures

- `sample/sample.eml` - synthetic message designed to exercise all three
  heuristics (two Received hops, Reply-To domain mismatch, `.scr` attachment).
  The attachment bytes are harmless text, not executable content.
- `sample/findings.csv` - synthetic findings using common header variants.
- `sample/trace.json` - synthetic offline tool trace with a valid record hash.

## Exit codes

- `0` - completed.
- `2` - input/operational error (missing file, bad JSON, command failure).

This toolkit is a local evidence viewer. It does not replace an email gateway,
EDR, firewall management console, or a full verdict engine.
