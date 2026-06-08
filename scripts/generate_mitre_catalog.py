#!/usr/bin/env python3
"""Generate the frontend MITRE ATT&CK Enterprise catalog from official STIX data."""

from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path
from typing import Any

SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
OUTPUT_PATH = Path(__file__).resolve().parents[1] / "frontend/src/mitreCatalog.ts"

TACTIC_NAMES = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "stealth": "Stealth",
    "defense-impairment": "Defense Impairment",
}

TACTIC_HINTS = {
    "Reconnaissance": "External intelligence, exposed asset inventory, domain and web telemetry",
    "Resource Development": "Infrastructure inventory, certificate logs, domain registration data, cloud asset records",
    "Initial Access": "Email security logs, proxy logs, identity logs, endpoint process and file telemetry",
    "Execution": "Process creation, command line, script block, shell history, EDR execution telemetry",
    "Persistence": "Registry, scheduled task, service, startup item, account, and cloud control-plane audit logs",
    "Privilege Escalation": "Process, token, service, kernel, account, and privilege assignment telemetry",
    "Defense Evasion": "Security control logs, process/file/registry telemetry, policy changes, tamper events",
    "Stealth": "Security control logs, process/file/registry telemetry, policy changes, tamper events",
    "Defense Impairment": "Security control logs, process/file/registry telemetry, policy changes, tamper events",
    "Credential Access": "Authentication logs, process access, memory access, file access, identity provider audit logs",
    "Discovery": "Process command line, directory service queries, cloud inventory calls, network enumeration logs",
    "Lateral Movement": "Authentication logs, remote service activity, SMB/RDP/SSH telemetry, EDR network events",
    "Collection": "File access, clipboard, screen capture, database, email, and cloud storage audit logs",
    "Command and Control": "DNS, proxy, firewall, TLS metadata, EDR network connections, NetFlow",
    "Exfiltration": "Proxy, firewall, DLP, cloud storage, email gateway, and network volume telemetry",
    "Impact": "File modification, service stop, backup deletion, encryption activity, availability monitoring",
}

STEP_HINTS = {
    "Reconnaissance": ("Define external surface", "Identify observable reconnaissance indicators and target scope"),
    "Resource Development": ("Review adversary infrastructure clues", "Collect domains, certificates, cloud assets, or tooling references related to the hypothesis"),
    "Initial Access": ("Trace initial entry evidence", "Review delivery vector, user interaction, and first execution telemetry"),
    "Execution": ("Review execution telemetry", "Search process, script, shell, and command-line activity matching the technique"),
    "Persistence": ("Inspect persistence locations", "Review newly created or modified services, tasks, accounts, registry keys, cloud objects, and startup paths"),
    "Privilege Escalation": ("Validate privilege change", "Correlate exploit, token, service, or account changes with elevated execution"),
    "Defense Evasion": ("Review evasion indicators", "Search for tampering, obfuscation, policy change, suspicious rename, and control bypass activity"),
    "Stealth": ("Review stealth indicators", "Search for tampering, obfuscation, policy change, suspicious rename, and control bypass activity"),
    "Defense Impairment": ("Review impairment indicators", "Search for security control changes, logging gaps, disable events, and tamper alerts"),
    "Credential Access": ("Hunt credential access telemetry", "Search process access, authentication anomalies, secrets access, and credential store activity"),
    "Discovery": ("Review enumeration activity", "Search commands, API calls, and queries that enumerate users, systems, network, or cloud resources"),
    "Lateral Movement": ("Correlate source and destination", "Review remote logon, file copy, remote execution, and service creation across hosts"),
    "Collection": ("Identify collection staging", "Search file access, archive creation, screenshots, clipboard, email, database, or cloud storage reads"),
    "Command and Control": ("Analyze outbound communications", "Review rare destinations, beacon intervals, user agents, ports, and process-to-network context"),
    "Exfiltration": ("Review outbound transfer patterns", "Search unusual upload volume, cloud storage writes, archive transfer, and external destination anomalies"),
    "Impact": ("Validate impact activity", "Review destructive commands, encryption, service stoppage, backup deletion, and availability changes"),
}


def clean_description(value: str) -> str:
    description = re.sub(r"\(Citation:.*?\)", "", value)
    return " ".join(description.split())


def attack_reference(obj: dict[str, Any]) -> dict[str, Any] | None:
    for reference in obj.get("external_references", []):
        external_id = reference.get("external_id", "")
        if reference.get("source_name") == "mitre-attack" and external_id.startswith("T"):
            return reference
    return None


def technique_url(technique_id: str, reference: dict[str, Any]) -> str:
    return reference.get(
        "url",
        f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
    )


def build_catalog(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    catalog = []
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        reference = attack_reference(obj)
        if not reference:
            continue

        phases = sorted(
            {
                TACTIC_NAMES.get(phase["phase_name"], phase["phase_name"].replace("-", " ").title())
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            }
        ) or ["Unmapped"]
        primary_tactic = phases[0]
        technique_id = reference["external_id"]
        technique_name = obj.get("name", "")
        platforms = obj.get("x_mitre_platforms", [])[:8]
        description = clean_description(obj.get("description", ""))
        short_description = description.split(". ")[0].strip()
        if len(short_description) > 260:
            short_description = short_description[:257].rstrip() + "..."

        data_sources = TACTIC_HINTS.get(
            primary_tactic,
            "Relevant endpoint, identity, network, cloud, and application telemetry",
        )
        if platforms:
            data_sources += " | Platforms: " + ", ".join(platforms)

        first_step = STEP_HINTS.get(
            primary_tactic,
            ("Review relevant telemetry", "Search telemetry and validate findings against the hypothesis"),
        )

        catalog.append(
            {
                "tactic": ", ".join(phases),
                "technique_id": technique_id,
                "technique": technique_name,
                "description": short_description or technique_name,
                "platforms": platforms,
                "url": technique_url(technique_id, reference),
                "data_sources": data_sources,
                "expected_evidence": (
                    f"Evidence should validate {technique_id} {technique_name}: "
                    f"{short_description or 'review behavior described by ATT&CK and correlate with local telemetry.'}"
                ),
                "false_positives": (
                    "Administrative activity, sanctioned automation, software deployment, vulnerability "
                    "management, backup, or normal platform behavior can overlap. Validate user, asset, "
                    "parent process, timing, and change context."
                ),
                "response": (
                    "Document confirmed indicators, scope affected users/assets, preserve relevant evidence, "
                    "tune detections, and escalate containment or remediation based on confidence and impact."
                ),
                "steps": [
                    f"{first_step[0]} | {first_step[1]}",
                    (
                        "Correlate entity context | Pivot across user, host, process, IP, domain, "
                        f"cloud resource, and time window related to {technique_id}."
                    ),
                    (
                        "Record evidence and judgement | Save supporting artifacts, explain false-positive "
                        "assessment, and mark each step status."
                    ),
                ],
                "queries": [
                    (
                        f"KQL | // Starter hunt for {technique_id} {technique_name}\n"
                        "// Replace table and fields with your telemetry source.\n"
                        f'search "{technique_id}" or "{technique_name}"'
                    ),
                    (
                        f"Sigma | title: Hunt for {technique_id} {technique_name}\n"
                        "status: experimental\n"
                        "description: Starter placeholder generated from MITRE ATT&CK mapping\n"
                        "logsource:\n"
                        "  product: windows\n"
                        "detection:\n"
                        "  keywords:\n"
                        f"    - '{technique_name.replace(chr(39), chr(39) + chr(39))}'\n"
                        "  condition: keywords"
                    ),
                ],
            }
        )

    return sorted(catalog, key=lambda item: (item["tactic"], item["technique_id"], item["technique"]))


def render_typescript(catalog: list[dict[str, Any]]) -> str:
    return (
        "export type MitreTechnique = {\n"
        "  tactic: string;\n"
        "  technique_id: string;\n"
        "  technique: string;\n"
        "  description: string;\n"
        "  platforms: string[];\n"
        "  url: string;\n"
        "  data_sources: string;\n"
        "  expected_evidence: string;\n"
        "  false_positives: string;\n"
        "  response: string;\n"
        "  steps: string[];\n"
        "  queries: string[];\n"
        "};\n\n"
        "// Generated from MITRE ATT&CK Enterprise STIX attack-pattern objects.\n"
        "// Source: https://github.com/mitre-attack/attack-stix-data/tree/master/enterprise-attack\n"
        f"export const mitreCatalog: MitreTechnique[] = {json.dumps(catalog, ensure_ascii=False, indent=2)};\n"
    )


def main() -> None:
    with urllib.request.urlopen(SOURCE_URL, timeout=90) as response:
        bundle = json.loads(response.read().decode("utf-8"))

    catalog = build_catalog(bundle)
    OUTPUT_PATH.write_text(render_typescript(catalog), encoding="utf-8")
    print(f"Wrote {len(catalog)} MITRE ATT&CK techniques to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
