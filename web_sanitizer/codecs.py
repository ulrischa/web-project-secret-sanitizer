"""Conservative literal codecs. Never evaluate source code."""

import html
import json
import re


class Unsafe(ValueError):
    pass


def decode_value(raw, codec):
    if codec == "plain":
        return raw
    if codec.startswith("html"):
        return html.unescape(raw)
    if codec == "json":
        return json.loads('"' + raw + '"')
    if codec == "php-single":
        return re.sub(r"\\([\\'])", r"\1", raw)
    if codec == "env-single":
        if "\\" in raw:
            raise Unsafe("Ambiguous ENV escape")
        return raw
    if codec in ("env-double", "ini-double") and re.search(r"(?<!\\)\$", raw):
        raise Unsafe("Configuration interpolation")
    if codec.startswith("php") and re.search(r"(?<!\\)\$", raw):
        raise Unsafe("PHP interpolation")
    if codec == "js-template" and re.search(r"(?<!\\)\$\{", raw):
        raise Unsafe("JavaScript interpolation")
    result = []
    i = 0
    escapes = {
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "b": "\b",
        "f": "\f",
        "v": "\v",
        "0": "\0",
        "\\": "\\",
        '"': '"',
        "'": "'",
        "`": "`",
        "$": "$",
    }
    while i < len(raw):
        if raw[i] != "\\":
            result.append(raw[i])
            i += 1
            continue
        if i + 1 >= len(raw):
            raise Unsafe("Incomplete escape")
        c = raw[i + 1]
        if codec == "php-double" and c in ("'", "b", "`"):
            result.append("\\" + c)
            i += 2
        elif c in escapes:
            if c == "0" and i + 2 < len(raw) and raw[i + 2].isdigit():
                raise Unsafe("Legacy octal escape")
            result.append(escapes[c])
            i += 2
        elif c in ("x", "u"):
            length = 2 if c == "x" else 4
            digits = raw[i + 2 : i + 2 + length]
            if len(digits) != length or not re.fullmatch("[0-9a-fA-F]+", digits):
                raise Unsafe("Unsupported hexadecimal escape")
            value = int(digits, 16)
            if 0xD800 <= value <= 0xDFFF or (
                codec.startswith("php") and (c == "u" or value >= 128)
            ):
                raise Unsafe("Unsupported Unicode escape")
            result.append(chr(value))
            i += length + 2
        elif c in "\r\n" and codec.startswith("js"):
            i += 2
            if c == "\r" and i < len(raw) and raw[i] == "\n":
                i += 1
        else:
            raise Unsafe("Unsupported escape; review required")
    return "".join(result)


def encode_value(value, codec):
    if codec == "plain":
        # Plain destinations have no general escaping convention.
        if any(c in value for c in "\r\n\x00"):
            raise Unsafe("Multiline value moved into plain text")
        return value
    if codec.startswith("html"):
        escaped = html.escape(value, quote=True)
        if codec == "html-unquoted":
            escaped = re.sub(
                r"[\s=`]", lambda m: "&#" + str(ord(m.group())) + ";", escaped
            )
        return escaped
    if codec == "json":
        return json.dumps(value, ensure_ascii=False)[1:-1]
    if codec == "env-single":
        if any(c in value for c in "'\r\n\\"):
            raise Unsafe("Value cannot be represented in ENV single quotes")
        return value
    if codec == "php-single":
        return value.replace("\\", "\\\\").replace("'", "\\'")
    value = (
        value.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace("\0", "\\0")
    )
    quote = "'" if codec.endswith("single") else "`" if codec == "js-template" else '"'
    value = value.replace(quote, "\\" + quote)
    if codec in ("php-double", "env-double", "ini-double", "js-template"):
        value = value.replace("$", "\\$")
    return value
