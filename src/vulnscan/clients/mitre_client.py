"""MITRE ATT&CK mapper with embedded CWE-to-technique mappings."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# ─── Curated CWE → ATT&CK mapping ──────────────────────────────────────────
# Maps common CWE IDs to relevant MITRE ATT&CK tactics and techniques.
# This is an embedded static mapping since the full CAPEC-to-ATT&CK
# cross-reference is complex and requires periodic updates.

CWE_TO_ATTACK: dict[str, list[dict[str, str]]] = {
    # Injection vulnerabilities
    "CWE-78": [
        {
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "capec_id": "CAPEC-88",
        },
    ],
    "CWE-79": [
        {
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "technique_id": "T1189",
            "technique_name": "Drive-by Compromise",
            "capec_id": "CAPEC-86",
        },
        {
            "tactic_id": "TA0006",
            "tactic_name": "Credential Access",
            "technique_id": "T1539",
            "technique_name": "Steal Web Session Cookie",
            "capec_id": "CAPEC-61",
        },
    ],
    "CWE-89": [
        {
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "capec_id": "CAPEC-66",
        },
    ],
    "CWE-94": [
        {
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "capec_id": "CAPEC-242",
        },
    ],
    # Buffer and memory vulnerabilities
    "CWE-119": [
        {
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1203",
            "technique_name": "Exploitation for Client Execution",
            "capec_id": "CAPEC-100",
        },
        {
            "tactic_id": "TA0004",
            "tactic_name": "Privilege Escalation",
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escalation",
            "capec_id": "CAPEC-100",
        },
    ],
    "CWE-120": [
        {
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1203",
            "technique_name": "Exploitation for Client Execution",
            "capec_id": "CAPEC-100",
        },
    ],
    "CWE-125": [
        {
            "tactic_id": "TA0009",
            "tactic_name": "Collection",
            "technique_id": "T1005",
            "technique_name": "Data from Local System",
            "capec_id": "CAPEC-540",
        },
    ],
    "CWE-787": [
        {
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1203",
            "technique_name": "Exploitation for Client Execution",
            "capec_id": "CAPEC-100",
        },
        {
            "tactic_id": "TA0004",
            "tactic_name": "Privilege Escalation",
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escalation",
            "capec_id": "CAPEC-100",
        },
    ],
    # Authentication / Access Control
    "CWE-287": [
        {
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "capec_id": "CAPEC-114",
        },
    ],
    "CWE-306": [
        {
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "capec_id": "CAPEC-115",
        },
    ],
    "CWE-862": [
        {
            "tactic_id": "TA0004",
            "tactic_name": "Privilege Escalation",
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escalation",
            "capec_id": "CAPEC-122",
        },
    ],
    "CWE-863": [
        {
            "tactic_id": "TA0004",
            "tactic_name": "Privilege Escalation",
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escalation",
            "capec_id": "CAPEC-122",
        },
    ],
    # Deserialization
    "CWE-502": [
        {
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "capec_id": "CAPEC-586",
        },
        {
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "capec_id": "CAPEC-586",
        },
    ],
    # Path traversal
    "CWE-22": [
        {
            "tactic_id": "TA0009",
            "tactic_name": "Collection",
            "technique_id": "T1005",
            "technique_name": "Data from Local System",
            "capec_id": "CAPEC-126",
        },
    ],
    # SSRF
    "CWE-918": [
        {
            "tactic_id": "TA0043",
            "tactic_name": "Reconnaissance",
            "technique_id": "T1595",
            "technique_name": "Active Scanning",
            "capec_id": "CAPEC-664",
        },
    ],
    # Use after free
    "CWE-416": [
        {
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1203",
            "technique_name": "Exploitation for Client Execution",
            "capec_id": "CAPEC-100",
        },
        {
            "tactic_id": "TA0004",
            "tactic_name": "Privilege Escalation",
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escalation",
            "capec_id": "CAPEC-100",
        },
    ],
    # Cryptographic issues
    "CWE-327": [
        {
            "tactic_id": "TA0006",
            "tactic_name": "Credential Access",
            "technique_id": "T1557",
            "technique_name": "Adversary-in-the-Middle",
            "capec_id": "CAPEC-20",
        },
    ],
    # Information exposure
    "CWE-200": [
        {
            "tactic_id": "TA0009",
            "tactic_name": "Collection",
            "technique_id": "T1005",
            "technique_name": "Data from Local System",
            "capec_id": "CAPEC-116",
        },
    ],
    # Default / generic exploitation mapping for public-facing apps
    "CWE-NVD-noinfo": [
        {
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "capec_id": None,
        },
    ],
}


class MITREClient:
    """MITRE ATT&CK technique mapper based on CWE classifications."""

    def get_attack_mappings(
        self, cwe_ids: list[str]
    ) -> list[dict[str, str]]:
        """Map CWE IDs to ATT&CK tactics and techniques.

        Args:
            cwe_ids: List of CWE identifiers (e.g., ["CWE-79", "CWE-89"]).

        Returns:
            List of ATT&CK mapping dicts with tactic/technique info.
        """
        mappings: list[dict[str, str]] = []
        seen: set[str] = set()

        for cwe_id in cwe_ids:
            cwe_mappings = CWE_TO_ATTACK.get(cwe_id, [])
            for mapping in cwe_mappings:
                # Deduplicate by technique_id
                key = f"{mapping['tactic_id']}:{mapping['technique_id']}"
                if key not in seen:
                    seen.add(key)
                    mappings.append(mapping)

        return mappings

    def get_all_supported_cwes(self) -> list[str]:
        """Return all CWE IDs that have ATT&CK mappings."""
        return sorted(CWE_TO_ATTACK.keys())
