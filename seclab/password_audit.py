"""Évaluation de la robustesse d'un mot de passe (hors ligne, rien n'est stocké ni envoyé)."""
import math
import string

COMMON = {
    "123456", "password", "12345678", "qwerty", "azerty", "123456789", "111111", "motdepasse",
    "abc123", "password1", "iloveyou", "admin", "welcome", "letmein", "000000", "soleil",
    "azerty123", "doudou", "football", "marseille", "123123", "1234", "qwertyuiop", "admin123",
}


def charset_size(pw: str) -> int:
    size = 0
    if any(c in string.ascii_lowercase for c in pw): size += 26
    if any(c in string.ascii_uppercase for c in pw): size += 26
    if any(c in string.digits for c in pw): size += 10
    if any(not c.isalnum() for c in pw): size += 32
    return size


def entropy_bits(pw: str) -> float:
    """Estimation théorique : longueur × log2(taille du jeu de caractères). Surestime les mots du dictionnaire."""
    return len(pw) * math.log2(charset_size(pw)) if pw else 0.0


def audit(pw: str) -> dict:
    issues = []
    if pw.lower() in COMMON:
        issues.append("Mot de passe parmi les plus courants")
    if len(pw) < 12:
        issues.append("Moins de 12 caractères")
    if charset_size(pw) < 62:
        issues.append("Mélangez majuscules, minuscules et chiffres")
    if len(set(pw)) <= len(pw) // 2:
        issues.append("Trop de caractères répétés")
    bits = entropy_bits(pw)
    if pw.lower() in COMMON:
        level = "très faible"
    elif bits < 40:
        level = "faible"
    elif bits < 60:
        level = "moyen"
    else:
        level = "fort"
    return {"entropy_bits": round(bits, 1), "level": level, "issues": issues}
