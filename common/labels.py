"""Canonical attack-label normalization shared by training and runtime code."""

from __future__ import annotations

import math
import re
import unicodedata
from typing import Any


_CANONICAL_LABELS = {
    "benign": "BENIGN",
    "bot": "Bot",
    "ddos": "DDoS",
    "ddos_attempt": "DDoS",
    "dos goldeneye": "DoS GoldenEye",
    "dos hulk": "DoS Hulk",
    "dos slowhttptest": "DoS Slowhttptest",
    "dos slowloris": "DoS slowloris",
    "ftp-patator": "FTP-Patator",
    "heartbleed": "Heartbleed",
    "infiltration": "Infiltration",
    "portscan": "PortScan",
    "port scan": "PortScan",
    "port_scan": "PortScan",
    "ssh-patator": "SSH-Patator",
    "web attack - brute force": "Web Attack - Brute Force",
    "web attack - sql injection": "Web Attack - SQL Injection",
    "web attack - xss": "Web Attack - XSS",
}


def normalize_attack_label(value: Any) -> str:
    """Return one stable label for CICIDS and runtime attack-name variants."""

    if value is None:
        return ""
    if isinstance(value, float) and math.isnan(value):
        return ""

    normalized = unicodedata.normalize("NFKC", str(value)).strip()
    normalized = normalized.replace("\ufffd", "-")
    normalized = re.sub(r"[\u2010-\u2015\u2212]", "-", normalized)
    normalized = re.sub(r"\s*-\s*", "-", normalized)
    normalized = re.sub(r"-+", "-", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    normalized = normalized.replace("Web Attack-", "Web Attack - ")
    return _CANONICAL_LABELS.get(normalized.casefold(), normalized)
