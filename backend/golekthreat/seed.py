from sqlalchemy.orm import Session

from .models import Playbook, PlaybookQuery, PlaybookStep, Severity


SAMPLE_PLAYBOOKS = [
    {
        "slug": "gt-cred-001-lsass-dump",
        "title": "Possible LSASS Credential Dumping",
        "hypothesis": "An attacker may attempt to dump LSASS memory to extract credentials.",
        "severity": Severity.critical,
        "tactic": "Credential Access",
        "technique": "OS Credential Dumping: LSASS Memory",
        "technique_id": "T1003.001",
        "data_sources": "Sysmon, Windows Security, EDR process telemetry",
        "expected_evidence": "Suspicious process access to lsass.exe, dump file creation, known tooling names, or abnormal parent process.",
        "false_positives": "Legitimate EDR, backup, crash dump, or administrative troubleshooting tools.",
        "response": "Isolate host, collect memory/process artifacts, rotate exposed credentials, add detection for validated patterns.",
        "steps": [
            ("Review LSASS access events", "Search process access telemetry targeting lsass.exe."),
            ("Validate process lineage", "Inspect parent-child process chain and signer reputation."),
            ("Hunt for dump artifacts", "Look for .dmp files in temp, user profile, and suspicious working directories."),
        ],
        "queries": [
            ("Sigma", "selection:\n  TargetImage|endswith: '\\\\lsass.exe'\ncondition: selection"),
            ("KQL", "DeviceProcessEvents | where ProcessCommandLine has_any ('lsass', 'comsvcs.dll', 'MiniDump')"),
        ],
    },
    {
        "slug": "gt-def-001-encoded-powershell",
        "title": "Suspicious PowerShell Encoded Command",
        "hypothesis": "Encoded PowerShell may indicate obfuscated execution used for initial access, payload staging, or defense evasion.",
        "severity": Severity.high,
        "tactic": "Defense Evasion",
        "technique": "Obfuscated Files or Information",
        "technique_id": "T1027",
        "data_sources": "PowerShell logs, Sysmon process creation, EDR command line telemetry",
        "expected_evidence": "EncodedCommand flags, long base64-like strings, network download cradle, unusual parent process.",
        "false_positives": "Admin scripts, endpoint management, software deployment tasks.",
        "response": "Decode command, identify payload source, block infrastructure, create detection for parent and command patterns.",
        "steps": [
            ("Find encoded invocations", "Search for -enc, -encodedcommand, and base64-like payloads."),
            ("Decode suspicious commands", "Decode payload and classify intent."),
            ("Pivot to network indicators", "Extract URLs, domains, and IPs from decoded commands."),
        ],
        "queries": [
            ("KQL", "DeviceProcessEvents | where FileName =~ 'powershell.exe' and ProcessCommandLine has_any ('-enc','-encodedcommand')"),
            ("Splunk", "index=* powershell (\"-enc\" OR \"-encodedcommand\")"),
        ],
    },
    {
        "slug": "gt-lat-001-admin-share",
        "title": "Unusual Admin Share Lateral Movement",
        "hypothesis": "An attacker may use admin shares to stage tools or move laterally between Windows hosts.",
        "severity": Severity.high,
        "tactic": "Lateral Movement",
        "technique": "SMB/Windows Admin Shares",
        "technique_id": "T1021.002",
        "data_sources": "Windows Security logs, SMB telemetry, EDR file and process events",
        "expected_evidence": "Admin share access, remote service creation, suspicious file copy, new process on remote host.",
        "false_positives": "Software deployment, backup operations, domain administration.",
        "response": "Confirm operator account, isolate affected hosts, remove staged tooling, review lateral movement blast radius.",
        "steps": [
            ("Identify admin share access", "Search for C$, ADMIN$, and IPC$ access patterns."),
            ("Correlate file writes", "Find files written shortly before remote execution."),
            ("Review authentication path", "Validate account, source host, and destination host relationships."),
        ],
        "queries": [
            ("Sigma", "selection:\n  ShareName|contains: ['C$', 'ADMIN$']\ncondition: selection"),
            ("Elastic", "event.category:network and file.path:(*\\\\C$\\\\* or *\\\\ADMIN$\\\\*)"),
        ],
    },
]


def seed_playbooks(db: Session) -> None:
    if db.query(Playbook).count() > 0:
        return

    for item in SAMPLE_PLAYBOOKS:
        playbook = Playbook(
            slug=item["slug"],
            title=item["title"],
            hypothesis=item["hypothesis"],
            severity=item["severity"],
            tactic=item["tactic"],
            technique=item["technique"],
            technique_id=item["technique_id"],
            data_sources=item["data_sources"],
            expected_evidence=item["expected_evidence"],
            false_positives=item["false_positives"],
            response=item["response"],
        )
        db.add(playbook)
        db.flush()

        for index, (title, instruction) in enumerate(item["steps"], start=1):
            db.add(
                PlaybookStep(
                    playbook_id=playbook.id,
                    position=index,
                    title=title,
                    instruction=instruction,
                )
            )

        for platform, query in item["queries"]:
            db.add(PlaybookQuery(playbook_id=playbook.id, platform=platform, query=query))

    db.commit()
