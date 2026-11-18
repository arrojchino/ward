#!/usr/bin/env python3
"""Unified local SOC toolkit (read-only, stdlib only).

Subcommands:
  analyze-eml FILE        Parse an EML, hash it, list evidence headers and
                          attachments, and emit explicitly-labeled heuristics.
  connections             Read established TCP connections from netstat -ano
                          (or --input JSON). Never opens sockets.
  firewall-rules          Read Windows firewall rules via Get-NetFirewallRule
                          (or --input CSV). Never modifies anything.
  normalize-findings CSV  Normalize a scanner findings CSV to a canonical
                          schema, accepting common header variants.
  verify-trace FILE       Heuristically check evidence-field presence and
                          record-hash consistency of a JSON tool trace.

All operations are local and read-only. No remote host is scanned, no email
content is executed, no credentials are handled, and no system configuration
is modified. Heuristics are indicators, never verdicts.
"""

from __future__ import annotations

import argparse
import csv
import email
import email.parser
import email.policy
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from email.utils import parseaddr

VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Canonical scanner findings schema (from the knowledge base) and the
# common header/variant spellings accepted on input.
# ---------------------------------------------------------------------------
CANONICAL_COLUMNS = [
    "Application Name",
    "Application ID",
    "Custom Severity Name",
    "CVE ID",
    "CWE ID",
    "Flaw Name",
    "First Found Date",
    "Filename/Class",
    "Finding Status",
    "Fixed Date",
    "Team Name",
    "Days to Resolve",
    "Scan Type",
]

HEADER_VARIANTS = {
    "Application Name": ["app_name", "application_name", "application.name",
                         "app name", "application name", "application"],
    "Application ID": ["app_id", "application_id", "application.id",
                       "app id", "application id"],
    "Custom Severity Name": ["custom_severity", "custom_severity_name",
                             "severity", "severity name", "custom severity",
                             "custom severity name"],
    "CVE ID": ["cve_id", "cve", "cve id", "cveid"],
    "CWE ID": ["cwe_id", "cwe", "cwe id", "cweid"],
    "Flaw Name": ["flaw_name", "finding_category.name", "flaw name",
                  "finding category", "finding_category"],
    "First Found Date": ["first_found_date", "found_date", "first found date",
                         "found date", "firstfounddate"],
    "Filename/Class": ["file_name", "filename", "file_path", "source_file",
                       "filename/class", "file name/class", "filename class",
                       "file name", "file path", "source file"],
    "Finding Status": ["finding_status", "status", "resolution_status",
                       "finding status", "resolution status"],
    "Fixed Date": ["fixed_date", "resolution_date", "fixed date",
                   "resolution date"],
    "Team Name": ["team_name", "team", "business_unit", "team name",
                  "business unit"],
    "Scan Type": ["scan_type", "analysis_type", "scan type", "analysis type"],
    "Days to Resolve": ["days_to_resolve", "days to resolve"],
}

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".pif", ".js", ".jse", ".vbs", ".vbe", ".hta", ".ps1",
    ".bat", ".cmd", ".com", ".jar", ".lnk", ".msi", ".msp", ".iso", ".img",
    ".py", ".rb", ".sh", ".reg", ".关",  # last token intentionally inert
}

DATE_FORMATS = [
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%Y-%m-%d",
    "%m/%d/%Y",
]

DISCLAIMER_HEURISTIC = (
    "Heuristic indicators only; not a verdict. No verdict of maliciousness or "
    "authenticity is asserted. Authentication results are reported from headers "
    "and are not independently verified."
)
DISCLAIMER_TRACE = (
    "Heuristic consistency check modeled on redline: verifies required evidence "
    "fields are present and that the recorded hash matches the record. It does "
    "NOT establish authenticity, real-world events, causation, or that captured "
    "commands were actually executed. No captured content was executed and no "
    "remote target was contacted."
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _norm_header(name: str) -> str:
    """Normalize a header spelling for variant lookup."""
    s = name.strip().lower()
    for ch in ("_", ".", "/", "-"):
        s = s.replace(ch, " ")
    return re.sub(r"\s+", " ", s).strip()


VARIANT_LOOKUP = {}
for _canon, _variants in HEADER_VARIANTS.items():
    for _v in _variants:
        VARIANT_LOOKUP[_norm_header(_v)] = _canon


def _parse_date(value: str):
    """Best-effort date parse using known formats; returns datetime or None."""
    if not value:
        return None
    v = value.strip()
    if not v:
        return None
    # tolerate trailing 'Z'
    if v.endswith("Z"):
        v = v[:-1] + "+0000"
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(v, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(v)
    except ValueError:
        return None


def _days_to_resolve(first: str, fixed: str):
    """Return integer days between first-found and fixed dates, or ''."""
    d1, d2 = _parse_date(first), _parse_date(fixed)
    if d1 and d2:
        return str((d2 - d1).days)
    return ""


def _domain_of(addr: str):
    """Extract the domain part of a single RFC-style address."""
    _, mailbox = parseaddr(addr)
    if "@" in mailbox:
        return mailbox.rsplit("@", 1)[1].strip().lower()
    return ""


def _print_json(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


# ---------------------------------------------------------------------------
# 1. analyze-eml
# ---------------------------------------------------------------------------
def cmd_analyze_eml(args) -> int:
    path = args.file
    with open(path, "rb") as fh:
        raw = fh.read()

    raw_sha256 = hashlib.sha256(raw).hexdigest()
    msg = email.parser.BytesParser(policy=email.policy.default).parsebytes(raw)

    interest = ["From", "To", "Subject", "Date", "Received",
                "Authentication-Results"]
    headers = {h: msg.get_all(h, []) for h in interest}

    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            filename = part.get_filename()
            disposition = part.get_content_disposition()
            if filename or disposition == "attachment":
                attachments.append({
                    "filename": filename or "",
                    "content_type": part.get_content_type(),
                    "disposition": disposition or "",
                })

    # SPF/DKIM/DMARC results as reported in headers (never independently verified).
    auth_reported = []
    for line in headers["Authentication-Results"]:
        methods = {}
        for m in re.finditer(r"\b(spf|dkim|dmarc)\s*=\s*([A-Za-z0-9_]+)",
                             line, re.IGNORECASE):
            methods[m.group(1).lower()] = m.group(2).lower()
        auth_reported.append({"raw": line, "methods": methods})

    # ---- heuristics (explicitly labeled, never verdicts) ----
    flags = []

    received = headers["Received"]
    if len(received) > 1:
        flags.append({
            "flag": "multiple_received_hops",
            "kind": "heuristic",
            "detail": f"{len(received)} Received hops present (typical mail "
                      "delivery uses more than one hop; interpret in context).",
        })

    from_domains = {d for a in headers["From"] for d in [_domain_of(a)] if d}
    other_domains = {
        d for hdr in ("Reply-To", "Return-Path", "Sender")
        for a in msg.get_all(hdr, []) for d in [_domain_of(a)] if d
    }
    mismatches = sorted(from_domains - other_domains) if from_domains and other_domains else []
    if mismatches:
        flags.append({
            "flag": "sender_domain_mismatch",
            "kind": "heuristic",
            "detail": "From domain(s) differ from Reply-To/Return-Path/Sender "
                      "domain(s): " + ", ".join(mismatches),
        })

    for att in attachments:
        ext = os.path.splitext(att["filename"])[1].lower()
        if ext and ext in SUSPICIOUS_EXTENSIONS:
            flags.append({
                "flag": "suspicious_attachment_extension",
                "kind": "heuristic",
                "detail": f"Attachment '{att['filename']}' has extension '{ext}', "
                          "which is commonly associated with executable content.",
            })

    result = {
        "tool": "analyze-eml",
        "file": os.path.abspath(path),
        "size_bytes": len(raw),
        "sha256": raw_sha256,
        "headers_of_interest": headers,
        "authentication_results_reported": auth_reported,
        "attachments": attachments,
        "heuristic_flags": flags,
        "heuristic_flag_count": len(flags),
        "disclaimer": DISCLAIMER_HEURISTIC,
        "safety_note": "The file was parsed as data only. No email content was "
                       "executed, no URLs were opened, and no attachments were "
                       "written to disk.",
    }
    _print_json(result)
    return 0


# ---------------------------------------------------------------------------
# 2. connections (read-only)
# ---------------------------------------------------------------------------
_NETSTAT_RE = re.compile(
    r"^\s*(TCP\S*)\s+(\S+)\s+(\S+)\s+(ESTABLISHED)\s+(\d+)\s*$",
    re.IGNORECASE,
)


def _remote_scope(address: str) -> str:
    """Heuristic remote-address scope classification (no network access)."""
    host = address.rsplit(":", 1)[0]
    host = host.strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "unresolved"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private:
        return "private"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved:
        return "reserved"
    return "public"


def _parse_netstat(text: str):
    rows = []
    for line in text.splitlines():
        m = _NETSTAT_RE.match(line)
        if not m:
            continue
        proto, local, remote, state, pid = m.groups()
        rows.append({
            "proto": proto,
            "local_address": local,
            "remote_address": remote,
            "state": state.upper(),
            "pid": int(pid),
            "remote_scope_heuristic": _remote_scope(remote),
        })
    return rows


def _normalize_json_connections(data):
    if isinstance(data, dict):
        data = data.get("connections", data.get("data", []))
    rows = []
    for item in data:
        if not isinstance(item, dict):
            continue
        get = lambda *keys: next((item[k] for k in keys if k in item), "")
        remote = str(get("remote_address", "remote", "remote_addr", "raddr"))
        rows.append({
            "proto": str(get("proto", "protocol", "type")),
            "local_address": str(get("local_address", "local", "local_addr", "laddr")),
            "remote_address": remote,
            "state": str(get("state", "status")).upper() or "ESTABLISHED",
            "pid": get("pid", "process_id", "owner_pid"),
            "remote_scope_heuristic": _remote_scope(remote) if remote else "unresolved",
        })
    return [r for r in rows if r["state"] == "ESTABLISHED"]


def _print_table(rows, keys, headers):
    if not rows:
        print("(no rows)")
        return
    widths = []
    for i, header in enumerate(headers):
        key = keys[i]
        widths.append(max(len(header),
                          max(len(str(r.get(key, ""))) for r in rows)))
    fmt = "  ".join("{:<" + str(w) + "}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for r in rows:
        print(fmt.format(*[str(r.get(key, "")) for key in keys]))


def cmd_connections(args) -> int:
    if args.input:
        with open(args.input, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        rows = _normalize_json_connections(data)
        source = os.path.abspath(args.input)
    else:
        if os.name != "nt":
            print("WARNING: netstat is expected on Windows; attempting anyway.",
                  file=sys.stderr)
        proc = subprocess.run(
            ["netstat", "-ano", "-p", "TCP"],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode != 0:
            print(f"ERROR: netstat exited with code {proc.returncode}: "
                  f"{proc.stderr.strip()}", file=sys.stderr)
            return 2
        rows = _parse_netstat(proc.stdout)
        source = "netstat -ano -p TCP (local snapshot)"

    payload = {
        "tool": "connections",
        "source": source,
        "count": len(rows),
        "connections": rows,
        "disclaimer": "Read-only snapshot. Remote scope is a heuristic, not a "
                      "threat verdict. No sockets were opened and no remote "
                      "host was contacted.",
    }
    if args.json:
        _print_json(payload)
    else:
        print(f"CONNECTIONS | source: {source} | established TCP: {len(rows)}")
        _print_table(rows,
                     ["proto", "local_address", "remote_address", "state",
                      "pid", "remote_scope_heuristic"],
                     ["Proto", "Local Address", "Remote Address", "State",
                      "PID", "Scope*"])
        print("* Scope is a heuristic classification; not a verdict.")
    return 0


# ---------------------------------------------------------------------------
# 3. firewall-rules (read-only)
# ---------------------------------------------------------------------------
def _normalize_fw_row(row: dict) -> dict:
    get = lambda *keys: next((row[k] for k in keys if k in row), "")
    return {
        "name": str(get("Name", "name", "DisplayName", "displayname", "Rule Name")),
        "direction": str(get("Direction", "direction")),
        "action": str(get("Action", "action")),
        "enabled": str(get("Enabled", "enabled", "State", "state")),
    }


def _read_fw_csv(path: str):
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        return [_normalize_fw_row(r) for r in csv.DictReader(fh)]


def _read_fw_live():
    ps = ("Get-NetFirewallRule | Select-Object Name,DisplayName,Direction,"
          "Action,Enabled | ConvertTo-Json -Compress -Depth 2")
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"PowerShell exited {proc.returncode}: "
                           f"{proc.stderr.strip()}")
    text = proc.stdout.strip()
    if not text:
        return []
    data = json.loads(text)
    if isinstance(data, dict):
        data = [data]
    # Prefer DisplayName as the human-facing name when available.
    rows = []
    for item in data:
        rows.append({
            "name": str(item.get("DisplayName") or item.get("Name") or ""),
            "direction": str(item.get("Direction", "")),
            "action": str(item.get("Action", "")),
            "enabled": str(item.get("Enabled", "")),
        })
    return rows


def cmd_firewall_rules(args) -> int:
    if args.input:
        try:
            rows = _read_fw_csv(args.input)
            source = os.path.abspath(args.input)
        except Exception as exc:
            print(f"ERROR reading firewall CSV: {exc}", file=sys.stderr)
            return 2
    else:
        if os.name != "nt":
            print("ERROR: live firewall read requires Windows; use --input CSV.",
                  file=sys.stderr)
            return 2
        try:
            rows = _read_fw_live()
            source = "Get-NetFirewallRule (local, read-only)"
        except Exception as exc:
            print(f"ERROR reading firewall rules: {exc}", file=sys.stderr)
            return 2

    payload = {
        "tool": "firewall-rules",
        "source": source,
        "count": len(rows),
        "firewall_rules": rows,
        "disclaimer": "Read-only view. No firewall rule was created, changed, "
                      "or deleted. Rule presence does not prove a connection "
                      "will be allowed or blocked.",
    }
    if args.json:
        _print_json(payload)
    else:
        print(f"FIREWALL RULES | source: {source} | rules: {len(rows)}")
        _print_table(rows, ["name", "direction", "action", "enabled"],
                     ["Name", "Direction", "Action", "Enabled"])
    return 0


# ---------------------------------------------------------------------------
# 4. normalize-findings
# ---------------------------------------------------------------------------
def cmd_normalize_findings(args) -> int:
    with open(args.csv, "r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        source_fields = reader.fieldnames or []
        mapping = {}
        for field in source_fields:
            canon = VARIANT_LOOKUP.get(_norm_header(field))
            if canon:
                mapping[field] = canon

        normalized = []
        for raw_row in reader:
            row = {c: "" for c in CANONICAL_COLUMNS}
            for src, canon in mapping.items():
                row[canon] = (raw_row.get(src) or "").strip()
            row["Days to Resolve"] = _days_to_resolve(
                row["First Found Date"], row["Fixed Date"]
            )
            normalized.append(row)

    severity_counts = {}
    for row in normalized:
        sev = row["Custom Severity Name"] or "(unspecified)"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    if args.format == "json":
        payload = {
            "tool": "normalize-findings",
            "source": os.path.abspath(args.csv),
            "canonical_columns": CANONICAL_COLUMNS,
            "header_mapping": {s: c for s, c in mapping.items()},
            "count": len(normalized),
            "counts_by_severity": severity_counts,
            "findings": normalized,
        }
        rendered = json.dumps(payload, indent=2, ensure_ascii=False)
    else:
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=CANONICAL_COLUMNS)
        writer.writeheader()
        writer.writerows(normalized)
        rendered = buf.getvalue()

    if args.out:
        out_dir = os.path.dirname(os.path.abspath(args.out))
        if out_dir and not os.path.isdir(out_dir):
            os.makedirs(out_dir, exist_ok=True)
        with open(args.out, "w", encoding="utf-8", newline="") as fh:
            fh.write(rendered)
        print(f"WROTE {len(normalized)} normalized findings -> "
              f"{os.path.abspath(args.out)}")
    else:
        print(rendered, end="" if rendered.endswith("\n") else "\n")

    print("Counts by severity:")
    for sev in sorted(severity_counts):
        print(f"  {sev}: {severity_counts[sev]}")
    print(f"Total findings normalized: {len(normalized)}")
    print("Unmapped source columns: "
          + (", ".join(s for s in source_fields if s not in mapping) or "(none)"))
    return 0


# ---------------------------------------------------------------------------
# 5. verify-trace
# ---------------------------------------------------------------------------
def cmd_verify_trace(args) -> int:
    with open(args.file, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    scenario = data.get("scenario", {}) or {}
    required = scenario.get("required_evidence", []) or []
    evidence = data.get("evidence", {}) or {}

    missing = []
    for field in required:
        item = evidence.get(field)
        if not isinstance(item, dict) or not item.get("present"):
            missing.append(field)

    record = data.get("record")
    expected = data.get("record_sha256")
    computed = None
    consistent = None
    if record is not None and expected:
        canonical = json.dumps(record, sort_keys=True,
                               separators=(",", ":"), ensure_ascii=False)
        computed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        consistent = (computed == str(expected))

    if consistent is False:
        status = "inconsistent_record_hash_heuristic"
    elif consistent is True and not missing:
        status = "consistent_evidence_heuristic"
    else:
        status = "incomplete_or_unverifiable_evidence_heuristic"

    result = {
        "tool": "verify-trace",
        "trace_id": data.get("trace_id", ""),
        "scenario_name": scenario.get("name", ""),
        "adapter": scenario.get("adapter", ""),
        "target": scenario.get("target", ""),
        "required_evidence": required,
        "missing_evidence": missing,
        "hash_check": {
            "algorithm": "sha256",
            "computed": computed,
            "expected": expected,
            "consistent": consistent,
        },
        "status": status,
        "disclaimer": DISCLAIMER_TRACE,
    }
    _print_json(result)
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="toolkit.py",
        description="Unified local SOC toolkit (read-only, stdlib only). "
                    "Heuristics are indicators, never verdicts.",
        epilog="All commands are local and read-only: no remote scanning, no "
               "email execution, no credential handling, no system changes.",
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {VERSION}")
    sub = parser.add_subparsers(dest="command", metavar="{command}")

    p = sub.add_parser("analyze-eml",
                       help="parse an EML and emit evidence + heuristic flags")
    p.add_argument("file", help="path to a local .eml file")
    p.set_defaults(func=cmd_analyze_eml)

    p = sub.add_parser("connections",
                       help="read established TCP connections (read-only)")
    p.add_argument("--input", help="read connections from a JSON file instead "
                                   "of netstat")
    p.add_argument("--json", action="store_true",
                   help="emit JSON instead of a table")
    p.set_defaults(func=cmd_connections)

    p = sub.add_parser("firewall-rules",
                       help="read firewall rules (read-only, never modifies)")
    p.add_argument("--input", help="read rules from a CSV file instead of "
                                   "Get-NetFirewallRule")
    p.add_argument("--json", action="store_true",
                   help="emit JSON instead of a table")
    p.set_defaults(func=cmd_firewall_rules)

    p = sub.add_parser("normalize-findings",
                       help="normalize a scanner findings CSV")
    p.add_argument("csv", help="path to a findings CSV")
    p.add_argument("--out", help="write normalized output to this path")
    p.add_argument("--format", choices=["csv", "json"], default="csv",
                   help="output format (default: csv)")
    p.set_defaults(func=cmd_normalize_findings)

    p = sub.add_parser("verify-trace",
                       help="heuristically verify a JSON tool trace")
    p.add_argument("file", help="path to a JSON tool trace")
    p.set_defaults(func=cmd_verify_trace)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"ERROR: file not found: {exc.filename}", file=sys.stderr)
        return 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
