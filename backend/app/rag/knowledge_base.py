"""
CyberSleuth AI – MITRE ATT&CK Knowledge Base Loader
Member 1: AI/ML & Agent Architecture Lead

Loads MITRE-mapped scenario JSON and converts it to indexable chunks
for the RAG retriever.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class KBChunk:
    """A single indexable knowledge-base chunk."""
    chunk_id:    str
    title:       str
    text:        str                        # full text for embedding / search
    source:      str = "MITRE ATT&CK"
    technique_id: Optional[str] = None     # e.g. T1110.001
    tactic:      Optional[str] = None
    tags:        List[str] = field(default_factory=list)


class KnowledgeBase:
    """Loads and exposes MITRE-mapped scenario data as KB chunks."""

    # Built-in MITRE technique descriptions (covers the most common techniques
    # referenced in the evaluation golden set so the RAG can work without
    # an internet connection or large external file).
    BUILTIN_TECHNIQUES = [
        {
            "id": "T1110",
            "name": "Brute Force",
            "tactic": "Credential Access",
            "description": (
                "Adversaries may use brute force techniques to gain access to accounts when passwords are "
                "unknown or when password hashes are obtained. Without knowledge of the password for an "
                "account or set of accounts, an adversary may systematically guess the password using "
                "repetitive or iterative mechanisms. Brute forcing passwords can take place via interaction "
                "with a service that will check the validity of those credentials or offline against "
                "previously acquired credential data such as password hashes."
            ),
            "sub_techniques": [
                {
                    "id": "T1110.001",
                    "name": "Password Guessing",
                    "description": (
                        "Adversaries with no prior knowledge of legitimate credentials within the system "
                        "or environment may guess passwords to attempt access to accounts. Guessing may be "
                        "performed iteratively by a human actor, or automated using a list of passwords."
                    ),
                },
                {
                    "id": "T1110.003",
                    "name": "Password Spraying",
                    "description": (
                        "Adversaries may use a single or small list of commonly used passwords against many "
                        "different accounts to attempt to acquire valid account credentials. Password spraying "
                        "uses one password (e.g. 'Password01'), or a small list of commonly used passwords, "
                        "that may still meet complexity requirements."
                    ),
                },
            ],
            "detection": (
                "Monitor authentication logs for system and application login failures of Valid Accounts. "
                "Specifically, look for many failed authentication attempts across various accounts that may "
                "result from password spraying techniques."
            ),
            "mitigations": [
                "Account Use Policies",
                "Multi-factor Authentication",
                "Password Policies",
            ],
        },
        {
            "id": "T1548",
            "name": "Abuse Elevation Control Mechanism",
            "tactic": "Privilege Escalation",
            "description": (
                "Adversaries may circumvent mechanisms designed to control elevate privileges to gain "
                "higher-level permissions. Most modern systems contain native elevation control mechanisms "
                "that are intended to limit privileges that a user can perform on a machine."
            ),
            "sub_techniques": [],
            "detection": (
                "Monitor the file system for files that have the setuid or setgid bits set, as well as for "
                "any use of sudo. Also monitor processes and command-line arguments for actions that could "
                "be taken to circumvent UAC."
            ),
            "mitigations": ["User Account Control", "Privileged Account Management"],
        },
        {
            "id": "T1078",
            "name": "Valid Accounts",
            "tactic": "Initial Access",
            "description": (
                "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining "
                "Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised "
                "credentials may be used to bypass access controls placed on various resources."
            ),
            "sub_techniques": [
                {
                    "id": "T1078.003",
                    "name": "Local Accounts",
                    "description": (
                        "Adversaries may obtain and abuse credentials of a local account as a means of "
                        "gaining Initial Access, Persistence, Privilege Escalation, and Defense Evasion."
                    ),
                }
            ],
            "detection": (
                "Correlate other security systems with login information (e.g., a user has an active login "
                "session but has not entered the building or VPN activity during off hours)."
            ),
            "mitigations": ["Privileged Account Management", "Multi-factor Authentication"],
        },
        {
            "id": "T1021",
            "name": "Remote Services",
            "tactic": "Lateral Movement",
            "description": (
                "Adversaries may use Valid Accounts to log into a service specifically designed to accept "
                "remote connections, such as telnet, SSH, and VNC."
            ),
            "sub_techniques": [
                {
                    "id": "T1021.001",
                    "name": "Remote Desktop Protocol",
                    "description": (
                        "Adversaries may use Valid Accounts to log into a computer using the Remote Desktop "
                        "Protocol (RDP). The adversary may then perform actions as the logged-on user."
                    ),
                }
            ],
            "detection": (
                "Use of RDP may be legitimate, depending on the network environment and how it is used. "
                "Monitor for user accounts logged into systems they would not normally access or access "
                "during atypical hours."
            ),
            "mitigations": ["Network Segmentation", "Multi-factor Authentication"],
        },
        {
            "id": "T1071",
            "name": "Application Layer Protocol",
            "tactic": "Command and Control",
            "description": (
                "Adversaries may communicate using application layer protocols to avoid detection/network "
                "filtering by blending in with existing traffic. Commands to the remote system, and often "
                "the results of those commands, will be embedded within the protocol traffic between the "
                "client and server."
            ),
            "sub_techniques": [
                {
                    "id": "T1071.004",
                    "name": "DNS",
                    "description": (
                        "Adversaries may communicate using the Domain Name System (DNS) application layer "
                        "protocol to avoid detection/network filtering by blending in with existing traffic. "
                        "Commands to the remote system, and often the results of those commands, will be "
                        "embedded within the protocol traffic between the client and server."
                    ),
                }
            ],
            "detection": (
                "Analyze network data for uncommon data flows (e.g., a client sending significantly more "
                "data than it receives from a server). Processes utilizing the network that do not normally "
                "have network communication or have never been seen before are suspicious."
            ),
            "mitigations": ["Network Intrusion Prevention", "Filter Network Traffic"],
        },
    ]

    def __init__(self, extra_json_path: str | None = None):
        self._chunks: List[KBChunk] = []
        self._load_builtin()
        if extra_json_path and Path(extra_json_path).exists():
            self._load_scenarios(extra_json_path)

    def _load_builtin(self):
        for t in self.BUILTIN_TECHNIQUES:
            chunk_id = f"mitre_{t['id'].lower().replace('.', '_')}_overview"
            full_text = (
                f"{t['name']} ({t['id']})\n"
                f"Tactic: {t['tactic']}\n\n"
                f"{t['description']}\n\n"
                f"Detection: {t.get('detection', '')}\n"
                f"Mitigations: {', '.join(t.get('mitigations', []))}"
            )
            self._chunks.append(KBChunk(
                chunk_id=chunk_id,
                title=f"{t['name']} - {t['id']}",
                text=full_text,
                technique_id=t["id"],
                tactic=t["tactic"],
                tags=[t["id"], t["name"], t["tactic"]],
            ))
            for sub in t.get("sub_techniques", []):
                sub_id = f"mitre_{sub['id'].lower().replace('.', '_')}_detail"
                sub_text = (
                    f"{sub['name']} ({sub['id']})\n"
                    f"Parent: {t['name']} ({t['id']})\n"
                    f"Tactic: {t['tactic']}\n\n"
                    f"{sub['description']}"
                )
                self._chunks.append(KBChunk(
                    chunk_id=sub_id,
                    title=f"{sub['name']} - {sub['id']}",
                    text=sub_text,
                    technique_id=sub["id"],
                    tactic=t["tactic"],
                    tags=[sub["id"], t["id"], t["name"], t["tactic"]],
                ))

    def _load_scenarios(self, path: str):
        """Load supplemental MITRE-mapped scenario data."""
        with open(path) as f:
            scenarios = json.load(f)

        for sc in scenarios:
            if not sc.get("mitre_technique_ids"):
                continue
            for tid in sc["mitre_technique_ids"]:
                chunk_id = f"scenario_{sc['scenario_id']}_{tid.lower().replace('.', '_')}"
                text = (
                    f"Scenario: {sc.get('scenario_name', '')} [{tid}]\n"
                    f"Tactic: {sc.get('mitre_tactic', '')}\n"
                    f"Detection: {sc.get('detection_signature', '')}"
                )
                self._chunks.append(KBChunk(
                    chunk_id=chunk_id,
                    title=f"{sc.get('scenario_name', '')} – {tid}",
                    text=text,
                    technique_id=tid,
                    tactic=sc.get("mitre_tactic"),
                    tags=sc.get("mitre_technique_names", []) + [tid],
                ))

    @property
    def chunks(self) -> List[KBChunk]:
        return self._chunks

    def get_by_id(self, chunk_id: str) -> KBChunk | None:
        return next((c for c in self._chunks if c.chunk_id == chunk_id), None)


# Module-level singleton (lazy-loaded)
_kb: KnowledgeBase | None = None


def get_knowledge_base(extra_json_path: str | None = None) -> KnowledgeBase:
    global _kb
    if _kb is None:
        _kb = KnowledgeBase(extra_json_path=extra_json_path)
    return _kb
