"""Local heuristics; results are evidence, never a completeness guarantee."""

import ipaddress
import math
import re
from collections import Counter
from functools import lru_cache

KEY = re.compile(
    r"(?:password|passwd|passphrase|pwd|secret|token|apikey|accesskey|privatekey|credential|authorization|authkey|connectionstring|dsn|username|userid|dbuser|smtpuser|mailuser|hostname|dbhost|smtphost|server|email|mailaddress|clientid|tenantid|accountid|connectionuri|databaseurl|databasehost|databaseuser|firstname|lastname|fullname|birthdate|dateofbirth|phone|telephone|mobile|streetaddress|postaladdress|ssn|iban|creditcard|socialsecurity)",
    re.I,
)
CONTROL = re.compile(
    r"(?:length|count|enabled|disabled|timeout|regex|pattern|label|placeholder|type|algorithm|format|policy|validation|visible|visibility|field|selector|error|message|hint|help|required|expires|expiry|ttl|refreshinterval)$",
    re.I,
)


def sensitive_key(key, extra=()):
    clean = re.sub("[^a-zA-Z0-9]", "", key).lower()
    if clean in {"useragent", "hostname_label", "maxusers"} or CONTROL.search(clean):
        return False
    return (
        clean
        in {
            "user",
            "host",
            "login",
            "pass",
            "database",
            "dbname",
            "recipient",
            "sender",
            "from",
            "to",
        }
        or bool(KEY.search(clean))
        or clean in {re.sub("[^a-zA-Z0-9]", "", x).lower() for x in extra}
    )


PATTERNS = [
    (
        "private-key",
        re.compile(
            r"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----[\s\S]*?-----END (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----"
        ),
    ),
    (
        "email",
        re.compile(
            r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}\b"
        ),
    ),
    (
        "url",
        re.compile(
            r"\b(?:https?|ftp|sftp|ssh|ldap[s]?|smb|mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis[s]?|amqp[s]?)://[^\s<>\"'`\\)\]}]+",
            re.I,
        ),
    ),
    (
        "provider-token",
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{30,255}|glpat-[A-Za-z0-9_-]{20,255}|xox[baprs]-[A-Za-z0-9-]{10,255}|(?:AKIA|ASIA)[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{35}|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,255}|[rs]k_live_[A-Za-z0-9]{16,255}|npm_[A-Za-z0-9]{30,255}|pypi-[A-Za-z0-9_-]{40,255}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{20,})\b"
        ),
    ),
    (
        "service-token",
        re.compile(
            r"\b(?:dckr_pat_[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{20,}|dop_v1_[a-f0-9]{64}|lin_api_[A-Za-z0-9]{20,}|hvs\.[A-Za-z0-9_-]{20,}|NRAK-[A-Za-z0-9]{20,}|sb_secret_[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{16,})\b"
        ),
    ),
    ("phone", re.compile(r"(?<![\w+])(?:\+|00)[1-9][0-9 ()/-]{8,20}[0-9](?!\w)")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
    ),
    (
        "authorization",
        re.compile(r"\b(?:Bearer|Basic)\s+([A-Za-z0-9+/_.=-]{8,})", re.I),
    ),
    (
        "internal-domain",
        re.compile(
            r"\b(?:[a-zA-Z0-9-]+\.)+(?:internal|intern|local|lan|corp|intranet)\b", re.I
        ),
    ),
    (
        "windows-path",
        re.compile(
            r'(?:[A-Za-z]:\\(?:Users|Documents and Settings)\\[^\s\\/"\']+|\\\\[\w.-]+\\[\w$.-]+)',
            re.I,
        ),
    ),
    ("home-path", re.compile(r'/(?:home|Users)/[^\s/"\']+')),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b")),
]


def entropy(value):
    return (
        -sum(
            (n / len(value)) * math.log2(n / len(value))
            for n in Counter(value).values()
        )
        if value
        else 0
    )


def detect(text, custom_values=(), custom_patterns=()):
    hits = []
    for kind, pattern in PATTERNS:
        for m in pattern.finditer(text):
            group = 1 if kind == "authorization" else 0
            hits.append((m.start(group), m.end(group), kind))
    for m in re.finditer(
        r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:]{0,39}(?![\w:])",
        text,
    ):
        try:
            ipaddress.ip_address(m.group())
            hits.append((m.start(), m.end(), "ip-address"))
        except ValueError:
            pass
    for m in re.finditer(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)", text):
        digits = [int(c) for c in m.group() if c.isdigit()]
        total = sum(
            (v * 2 - 9 if v * 2 > 9 else v * 2) if i % 2 == 1 else v
            for i, v in enumerate(reversed(digits))
        )
        if len(set(digits)) > 1 and total % 10 == 0:
            hits.append((m.start(), m.end(), "payment-card"))
    long_values = tuple(sorted(set(v for v in custom_values if len(v) >= 4)))
    if long_values:
        for m in value_pattern(long_values).finditer(text):
            hits.append((m.start(), m.end(), "custom-value"))
    for value in set(v for v in custom_values if 0 < len(v) < 4):
        for m in re.finditer(r"(?<!\w)" + re.escape(value) + r"(?!\w)", text):
            hits.append((m.start(), m.end(), "custom-value"))
    for pattern in custom_patterns:
        for m in re.finditer(pattern, text):
            if m.start() != m.end():
                hits.append((m.start(), m.end(), "custom-pattern"))
    return hits


@lru_cache(maxsize=4)
def value_pattern(values):
    return re.compile(
        "|".join(re.escape(v) for v in sorted(values, key=len, reverse=True))
    )
