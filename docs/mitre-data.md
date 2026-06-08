# MITRE ATT&CK Data

GolekThreat uses MITRE ATT&CK Enterprise technique data to make playbook mapping
fast and consistent.

## Source

- ATT&CK website: https://attack.mitre.org/
- ATT&CK data and tools: https://attack.mitre.org/resources/attack-data-and-tools/
- STIX repository: https://github.com/mitre-attack/attack-stix-data

## Generated File

The generated catalog lives at:

```text
frontend/src/mitreCatalog.ts
```

It contains active Enterprise `attack-pattern` objects only. Revoked and
deprecated techniques are skipped.

## Regeneration

```bash
python scripts/generate_mitre_catalog.py
```

The script downloads the current Enterprise ATT&CK STIX bundle and writes a
TypeScript catalog. Review the generated diff before committing.

## Helper Fields

Recent ATT&CK STIX technique objects do not expose technique-specific data
sources directly on every `attack-pattern`. GolekThreat derives practical helper
text from tactic, platform, and technique description. Treat generated fields as
starter guidance, not final detection engineering content.
