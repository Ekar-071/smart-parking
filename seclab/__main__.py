import argparse
import sys

from . import log_analyzer, password_audit, secret_scanner


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="seclab", description="Petits outils de sécurité défensive")
    sub = p.add_subparsers(dest="cmd", required=True)
    lg = sub.add_parser("logs", help="Détecter la force brute SSH dans auth.log")
    lg.add_argument("file")
    lg.add_argument("--threshold", type=int, default=5)
    pw = sub.add_parser("password", help="Auditer un mot de passe (saisie masquée)")
    pw.add_argument("--value", help="À éviter : visible dans l'historique du shell")
    sc = sub.add_parser("secrets", help="Chercher des secrets dans un dossier")
    sc.add_argument("path", nargs="?", default=".")
    args = p.parse_args(argv)

    if args.cmd == "logs":
        try:
            with open(args.file, encoding="utf-8", errors="replace") as f:
                print(log_analyzer.format_report(log_analyzer.analyze(f, args.threshold), args.threshold))
        except OSError as e:
            print(f"Erreur : {e}", file=sys.stderr)
            return 1
    elif args.cmd == "password":
        import getpass
        res = password_audit.audit(args.value or getpass.getpass("Mot de passe : "))
        print(f"Niveau : {res['level']} (≈ {res['entropy_bits']} bits)")
        for issue in res["issues"]:
            print(f"  - {issue}")
    else:
        findings = secret_scanner.scan_dir(args.path)
        for path, items in findings.items():
            for lineno, label, masked in items:
                print(f"{path}:{lineno}  {label}  {masked}")
        print(f"{sum(map(len, findings.values()))} secret(s) potentiel(s) trouvé(s).")
        return 2 if findings else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
