"""Recherche de secrets accidentellement commités dans un dossier."""
import re
from pathlib import Path

PATTERNS = {
    "Clé d'accès AWS": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Clé privée": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Jeton GitHub": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "Secret générique": re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"),
}
SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__"}


def mask(value: str) -> str:
    return value[:4] + "…" + "*" * 4 if len(value) > 8 else "****"


def scan_text(text: str) -> list[tuple[int, str, str]]:
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for label, rx in PATTERNS.items():
            if m := rx.search(line):
                findings.append((lineno, label, mask(m.group(0))))
    return findings


def scan_dir(root: str) -> dict[str, list[tuple[int, str, str]]]:
    results = {}
    for path in Path(root).rglob("*"):
        if path.is_dir() or SKIP_DIRS & set(path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binaire ou illisible
        if found := scan_text(text):
            results[str(path)] = found
    return results
