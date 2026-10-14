import re
import ipaddress
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "payment",
    "bank",
    "paypal",
    "appleid",
    "microsoft",
    "crypto",
    "wallet",
    "signin",
    "password",
    "confirm",
]

SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".link",
    ".work",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
}

URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "rb.ly",
]

TYPO_DOMAINS = [
    "paypa1",
    "paypal-secure",
    "g00gle",
    "googie",
    "microsooft",
    "micros0ft",
    "amaz0n",
    "arnazon",
    "app1eid",
    "appleid-verify",
]


def get_verdict(score: int) -> str:
    if score >= 55:
        return "high_risk"
    if score >= 20:
        return "suspicious"
    return "safe"


def analyze_url(raw_url: str) -> dict:
    raw_url = (raw_url or "").strip()

    if not raw_url:
        return {"error": "Введите ссылку для проверки."}

    if len(raw_url) > 2048:
        return {"error": "Ссылка слишком длинная."}

    if any(ch.isspace() for ch in raw_url):
        return {"error": "URL не должен содержать пробелы."}

    parse_candidate = raw_url if "://" in raw_url else f"http://{raw_url}"

    try:
        parsed = urlparse(parse_candidate)
    except ValueError:
        return {"error": "Не удалось разобрать URL."}

    if parsed.scheme not in ("http", "https"):
        return {"error": "Поддерживаются только ссылки http:// и https://."}

    if not parsed.netloc:
        return {"error": "В ссылке не найден домен."}

    hostname = (parsed.hostname or "").lower()

    if not hostname:
        return {"error": "Некорректный домен в ссылке."}

    score = 0
    reasons = []

    if parsed.scheme != "https":
        score += 12
        reasons.append("Ссылка использует небезопасный протокол http.")

    try:
        ipaddress.ip_address(hostname)
        score += 35
        reasons.append("Вместо нормального домена используется IP-адрес.")
    except ValueError:
        pass

    if len(raw_url) > 90:
        score += 8
        reasons.append("URL выглядит подозрительно длинным.")

    if hostname.count(".") > 2:
        score += 12
        reasons.append("В домене слишком много уровней/поддоменов.")

    if "@" in parsed.netloc:
        score += 25
        reasons.append("В адресе есть символ @ — так часто маскируют настоящий домен.")

    if "--" in hostname:
        score += 10
        reasons.append("В домене есть двойной дефис.")

    if "%" in parsed.path or "%" in parsed.query:
        score += 8
        reasons.append("В URL есть закодированные символы, что может скрывать полезную нагрузку.")

    if len(parsed.query) > 80:
        score += 8
        reasons.append("У ссылки подозрительно длинный набор параметров.")

    if re.search(r"\d{6,}", raw_url):
        score += 12
        reasons.append("В URL есть длинная последовательность цифр.")

    if any(shortener in hostname for shortener in URL_SHORTENERS):
        score += 18
        reasons.append("Ссылка использует сервис сокращения URL.")

    lower_url = raw_url.lower()
    matched_keywords = [word for word in SUSPICIOUS_KEYWORDS if word in lower_url]

    if matched_keywords:
        keyword_score = min(25, 8 * len(matched_keywords))
        score += keyword_score
        preview = ", ".join(matched_keywords[:3])
        reasons.append(f"В ссылке есть слова, часто встречающиеся в фишинге: {preview}.")

    typo_matches = [typo for typo in TYPO_DOMAINS if typo in hostname]

    if typo_matches:
        score += 45
        preview = ", ".join(typo_matches[:3])
        reasons.append(f"Домен похож на известную компанию с опечаткой: {preview}.")

    labels = hostname.split(".")
    has_punycode = any(label.startswith("xn--") for label in labels)

    if has_punycode:
        score += 25
        reasons.append("Домен использует punycode — возможна подмена символов.")
    elif any(ord(ch) > 127 for ch in hostname):
        score += 20
        reasons.append("Домен содержит нестандартные символы.")

    if "." in hostname:
        tld = hostname.rsplit(".", 1)[-1]
        if f".{tld}" in SUSPICIOUS_TLDS:
            score += 16
            reasons.append(f"Используется подозрительная доменная зона: .{tld}.")

    score = max(0, min(100, score))

    return {
        "url": raw_url,
        "risk_score": score,
        "verdict": get_verdict(score),
        "reasons": reasons,
        "details": {
            "scheme": parsed.scheme,
            "hostname": hostname,
            "path": parsed.path,
            "query_length": len(parsed.query),
        },
    }