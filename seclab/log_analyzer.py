"""Détection de tentatives de force brute SSH dans un fichier auth.log."""
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")


@dataclass
class Report:
    failures: Counter = field(default_factory=Counter)
    users_tried: dict = field(default_factory=lambda: defaultdict(set))
    successes: dict = field(default_factory=lambda: defaultdict(list))
    suspects: list = field(default_factory=list)
    compromised: list = field(default_factory=list)


def analyze(lines, threshold: int = 5) -> Report:
    """Une IP est suspecte au-delà de `threshold` échecs ; 'compromise possible' si elle réussit ensuite une connexion."""
    rep = Report()
    failures_before_success: dict[str, int] = {}
    for line in lines:
        if m := FAILED.search(line):
            rep.failures[m["ip"]] += 1
            rep.users_tried[m["ip"]].add(m["user"])
        elif m := ACCEPTED.search(line):
            rep.successes[m["ip"]].append(m["user"])
            failures_before_success.setdefault(m["ip"], rep.failures[m["ip"]])
    rep.suspects = [ip for ip, n in rep.failures.most_common() if n >= threshold]
    rep.compromised = [ip for ip in rep.suspects if failures_before_success.get(ip, 0) >= threshold]
    return rep


def format_report(rep: Report, threshold: int) -> str:
    out = [f"IP suspectes (≥ {threshold} échecs) : {len(rep.suspects)}"]
    for ip in rep.suspects:
        out.append(f"  {ip:15s} {rep.failures[ip]:3d} échecs, {len(rep.users_tried[ip])} comptes essayés")
    for ip in rep.compromised:
        out.append(f"  !! {ip} a réussi une connexion après des échecs répétés : compte possiblement compromis")
    if not rep.suspects:
        out.append("  Rien à signaler.")
    return "\n".join(out)
