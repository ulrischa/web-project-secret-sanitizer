"""Syntax-aware analysis, byte ranges converted once to character positions."""

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
import fnmatch
import importlib
import re

from tree_sitter import Language, Parser
from .codecs import Unsafe, decode_value
from .detect import detect, sensitive_key, entropy

LANGUAGES = {
    ".php": "php",
    ".phtml": "php",
    ".php3": "php",
    ".php4": "php",
    ".php5": "php",
    ".inc": "php",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".json": "json",
}


@dataclass
class Region:
    start: int
    end: int
    codec: str
    value: str
    reason: str = ""


@dataclass
class Analysis:
    edits: list = field(default_factory=list)
    regions: list = field(default_factory=list)
    issues: list = field(default_factory=list)


@lru_cache(maxsize=8)
def parser(language):
    module = importlib.import_module(
        "tree_sitter_" + ("typescript" if language == "tsx" else language)
    )
    factory = (
        "language_php"
        if language == "php"
        else "language_typescript"
        if language == "typescript"
        else "language_tsx"
        if language == "tsx"
        else "language"
    )
    return Parser(Language(getattr(module, factory)()))


def walk(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.named_children))


def config_format(name, config):
    base = Path(name).name
    if base == ".env" or base.startswith(".env."):
        return "env"
    if Path(name).suffix.lower() == ".ini":
        return "ini"
    for pattern, adapter in config.get("all_values", {}).items():
        if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(base, pattern):
            return adapter
    return None


def analyze(name, text, config, known=()):
    result = Analysis()
    language = LANGUAGES.get(Path(name).suffix.lower())
    adapter = config_format(name, config)
    values = tuple(config.get("sensitive_values", [])) + tuple(known)
    patterns = config.get("patterns", [])

    def issue(start, reason):
        item = {"line": text.count("\n", 0, start) + 1, "reason": reason}
        if item not in result.issues:
            result.issues.append(item)

    def add(start, end, codec, reason="", force=False):
        raw = text[start:end]
        if not raw:
            return
        try:
            value = decode_value(raw, codec)
        except (Unsafe, ValueError):
            issue(start, "unsupported-escape-or-interpolation")
            return
        region = Region(start, end, codec, value, reason)
        result.regions.append(region)
        hits = detect(value, values, patterns)
        if force or hits:
            region.reason = reason or (hits[0][2] if hits else "sensitive-context")
            result.edits.append(region)
        elif any(
            sensitive_key(m.group(1), config.get("sensitive_keys", []))
            for m in re.finditer(
                r"""["']?([A-Za-z_][A-Za-z0-9_-]*)["']?\s*[:=]\s*[^\s]""", value
            )
        ):
            issue(start, "serialized-sensitive-content-review")
        elif (
            len(value) >= 24
            and re.fullmatch("[A-Za-z0-9+/=_-]+", value)
            and entropy(value) >= 4.5
        ):
            issue(start, "high-entropy-value-review")

    def add_plain_matches(start, end, codec="plain"):
        fragment = text[start:end]
        result.regions.append(Region(start, end, codec, fragment))
        hits = detect(fragment, values, patterns)
        # Include labelled credentials in comments and prose without changing the label.
        for m in re.finditer(
            r'(?im)\b([\w.-]+)\s*[:=]\s*(["\']?)([^\r\n;<>]+)', fragment
        ):
            if sensitive_key(m.group(1), config.get("sensitive_keys", [])):
                s, e = m.span(3)
                value = m.group(3).rstrip()
                if m.group(2):
                    value = value.split(m.group(2), 1)[0]
                value = value.split("*/", 1)[0].split("-->", 1)[0].rstrip()
                if value:
                    hits.append((s, s + len(value), "labelled-value"))
        for a, b, kind in hits:
            add(start + a, start + b, codec, kind, True)

    if adapter:
        if adapter not in ("env", "ini", "properties"):
            issue(0, "unsupported-config-adapter")
            return result
        offset = 0
        for line in text.splitlines(keepends=True):
            content = line.rstrip("\r\n")
            stripped = content.strip()
            if (
                not stripped
                or stripped.startswith(("#", ";"))
                or (adapter == "ini" and stripped.startswith("["))
            ):
                add_plain_matches(offset, offset + len(content))
                offset += len(line)
                continue
            m = re.match(r"\s*(?:export\s+)?[\w.\[\]-]+\s*[=:]\s*", content)
            if not m:
                issue(offset, "unsupported-config-line")
                offset += len(line)
                continue
            start = m.end()
            rest = content[start:]
            if rest.startswith(('"', "'")):
                quote = rest[0]
                closing = re.search(r"(?<!\\)" + re.escape(quote), rest[1:])
                if not closing:
                    issue(offset + start, "multiline-config-value-review")
                else:
                    end = start + 1 + closing.start()
                    codec = (
                        "env-single"
                        if quote == "'"
                        else ("ini-double" if adapter == "ini" else "env-double")
                    )
                    add(offset + start + 1, offset + end, codec, "config-value", True)
                    tail = content[end + 1 :]
                    if tail.strip() and not tail.lstrip().startswith(("#", ";")):
                        issue(offset + end, "unsupported-config-tail")
                    add_plain_matches(offset + end + 1, offset + len(content))
            else:
                # INI semicolons and dotenv whitespace-hash comments end an unquoted value.
                tail = re.search(r";" if adapter == "ini" else r"\s+#", rest)
                end = start + (tail.start() if tail else len(rest))
                end = len(content[:end].rstrip())
                raw = content[start:end]
                if "$" in raw or raw.endswith("\\"):
                    issue(offset + start, "config-interpolation-or-continuation")
                add(offset + start, offset + end, "plain", "config-value", True)
                add_plain_matches(offset + end, offset + len(content))
            offset += len(line)
    elif language:
        data = text.encode("utf-8")
        # Tree-sitter ranges are UTF-8 byte offsets, not Python string offsets.
        positions = [0] * (len(data) + 1)
        at = 0
        for i, char in enumerate(text):
            width = len(char.encode("utf-8"))
            for j in range(width):
                positions[at + j] = i
            at += width
        positions[at] = len(text)
        tree = parser(language).parse(data)
        if tree.root_node.has_error:
            issue(0, "source-syntax-error")
            return result
        nodes = list(walk(tree.root_node))
        forced = set()

        def raw(node):
            return data[node.start_byte : node.end_byte].decode("utf-8")

        definitions = {}
        for definition in nodes:
            lhs = rhs = None
            if definition.type == "assignment_expression":
                lhs = definition.child_by_field_name("left")
                rhs = definition.child_by_field_name("right")
            elif definition.type == "variable_declarator":
                lhs = definition.child_by_field_name("name")
                rhs = definition.child_by_field_name("value")
            if (
                lhs is not None
                and rhs is not None
                and lhs.type in ("identifier", "variable_name")
            ):
                definitions.setdefault(raw(lhs), []).append(rhs)
        tracing = set()

        def mark(node):
            if node is None:
                return
            if (
                node.type in ("argument", "parenthesized_expression")
                and len(node.named_children) == 1
            ):
                return mark(node.named_children[0])
            if node.type in ("object", "array", "array_creation_expression"):
                for leaf in walk(node):
                    if leaf.type in ("string", "encapsed_string", "template_string"):
                        parent = leaf.parent
                        is_key = (
                            parent.type == "pair"
                            and parent.child_by_field_name("key") == leaf
                        ) or (
                            parent.type == "array_element_initializer"
                            and len(parent.named_children) > 1
                            and parent.named_children[0] == leaf
                        )
                        if not is_key:
                            forced.add((leaf.start_byte, leaf.end_byte))
                return
            if node.type in ("string", "encapsed_string", "template_string"):
                forced.add((node.start_byte, node.end_byte))
            elif (
                node.type in ("identifier", "variable_name")
                and len(definitions.get(raw(node), [])) == 1
            ):
                name = raw(node)
                if name in tracing:
                    issue(positions[node.start_byte], "cyclic-sensitive-reference")
                    return
                tracing.add(name)
                mark(definitions[name][0])
                tracing.remove(name)
            elif raw(node).lower() not in ("null", "false", "true", "undefined", ""):
                issue(
                    positions[node.start_byte], "dynamic-or-nonstring-sensitive-value"
                )

        for node in nodes:
            key = value = None
            if node.type in (
                "assignment_expression",
                "augmented_assignment_expression",
            ):
                key = node.child_by_field_name("left")
                value = node.child_by_field_name("right")
            elif node.type in ("variable_declarator", "property_element"):
                key = node.child_by_field_name("name")
                value = node.child_by_field_name("value")
                if key is None and node.named_children:
                    key = node.named_children[0]
                if value is None and len(node.named_children) > 1:
                    value = node.named_children[-1]
            elif node.type in ("pair", "public_field_definition"):
                key = node.child_by_field_name("key") or node.child_by_field_name(
                    "name"
                )
                value = node.child_by_field_name("value")
            elif (
                node.type in ("array_element_initializer", "const_element")
                and len(node.named_children) >= 2
            ):
                key = node.named_children[0]
                value = node.named_children[-1]
            if key is not None and sensitive_key(
                raw(key), config.get("sensitive_keys", [])
            ):
                mark(value)
            if node.type in (
                "function_call_expression",
                "call_expression",
                "object_creation_expression",
                "new_expression",
            ):
                fun = node.child_by_field_name("function") or node.child_by_field_name(
                    "constructor"
                )
                if fun is None and node.named_children:
                    fun = node.named_children[0]
                args = node.child_by_field_name("arguments")
                if args is None:
                    args = next(
                        (n for n in node.named_children if n.type == "arguments"), None
                    )
                if fun is None or args is None:
                    continue
                fname = raw(fun).lower().lstrip("\\")
                arguments = list(args.named_children)

                def argtext(i):
                    return raw(arguments[i]) if len(arguments) > i else ""

                indexes = []
                if fname == "define" and sensitive_key(argtext(0)):
                    indexes = [1]
                if fname in ("mysqli_connect", "mysql_connect", "pdo", "mysqli"):
                    indexes = [0, 1, 2]
                if fname in ("pg_connect", "pg_pconnect"):
                    indexes = [0]
                if fname in ("curl_setopt",) and any(
                    x in argtext(1)
                    for x in (
                        "CURLOPT_USERPWD",
                        "CURLOPT_PROXYUSERPWD",
                        "CURLOPT_PASSWORD",
                        "CURLOPT_USERNAME",
                    )
                ):
                    indexes = [2]
                if fname.endswith(
                    ("setpassword", "setusername", "setsecret", "settoken", "setapikey")
                ):
                    indexes = [0]
                for index in indexes:
                    if index < len(arguments):
                        mark(arguments[index])
                if fname in (
                    "base64_decode",
                    "atob",
                    "hex2bin",
                    "eval",
                    "function",
                    "create_function",
                    "unserialize",
                ):
                    issue(positions[node.start_byte], "encoded-content-review")
        covered = []
        for node in nodes:
            start, end = positions[node.start_byte], positions[node.end_byte]
            if any(a <= start and end <= b for a, b in covered):
                continue
            if node.type in (
                "string",
                "encapsed_string",
                "template_string",
            ) and language not in ("html", "css"):
                source = text[start:end]
                if source[:1] not in ('"', "'", "`") or source[-1:] != source[:1]:
                    issue(start, "unsupported-string")
                    continue
                codec = (
                    "json"
                    if language == "json"
                    else ("php-single" if source[0] == "'" else "php-double")
                    if language == "php"
                    else "js-template"
                    if source[0] == "`"
                    else "js-single"
                    if source[0] == "'"
                    else "js-double"
                )
                dynamic = any(
                    n.type
                    in (
                        "template_substitution",
                        "variable_name",
                        "member_access_expression",
                    )
                    for n in walk(node)
                )
                if dynamic:
                    if (node.start_byte, node.end_byte) in forced or detect(
                        source, values, patterns
                    ):
                        issue(start, "interpolated-sensitive-string")
                    covered.append((start, end))
                    continue
                parent = node.parent
                is_key = parent is not None and (
                    (
                        parent.type == "pair"
                        and parent.child_by_field_name("key") == node
                    )
                    or (
                        parent.type == "array_element_initializer"
                        and len(parent.named_children) > 1
                        and parent.named_children[0] == node
                    )
                )
                if is_key:
                    if detect(source[1:-1], values, patterns):
                        issue(start, "sensitive-structure-key-review")
                else:
                    add(
                        start + 1,
                        end - 1,
                        codec,
                        force=(node.start_byte, node.end_byte) in forced,
                    )
                covered.append((start, end))
            elif "comment" in node.type:
                add_plain_matches(start, end)
                covered.append((start, end))
            elif node.type == "text" and language == "php":
                sub = analyze("fragment.html", text[start:end], config, known)
                for r in sub.regions:
                    r.start += start
                    r.end += start
                result.regions.extend(sub.regions)
                result.edits.extend(sub.edits)
                for item in sub.issues:
                    issue(start, "embedded-html-" + item["reason"])
                covered.append((start, end))
            elif node.type == "raw_text" and language == "html":
                kind = "js" if node.parent.type == "script_element" else "css"
                parentraw = raw(node.parent)
                if kind == "js" and re.search(
                    r'type\s*=\s*["\']application/(?:ld\+)?json', parentraw, re.I
                ):
                    kind = "json"
                sub = analyze("fragment." + kind, text[start:end], config, known)
                for r in sub.regions:
                    r.start += start
                    r.end += start
                result.regions.extend(sub.regions)
                result.edits.extend(sub.edits)
                for item in sub.issues:
                    issue(start, "embedded-" + item["reason"])
                covered.append((start, end))
            elif node.type == "attribute" and language == "html":
                kids = node.named_children
                if len(kids) > 1:
                    value = kids[-1]
                    a, b = positions[value.start_byte], positions[value.end_byte]
                    quote = text[a : a + 1]
                    attribute_codec = (
                        "html-double"
                        if quote == '"'
                        else "html-single"
                        if quote == "'"
                        else "html-unquoted"
                    )
                    if quote in ('"', "'"):
                        a += 1
                        b -= 1
                    key = raw(kids[0])
                    if key.lower().startswith("on"):
                        if sensitive_key(text[a:b]) or detect(
                            text[a:b], values, patterns
                        ):
                            issue(a, "inline-event-handler-review")
                    else:
                        related_sensitive = False
                        if key.lower() in ("value", "content"):
                            for sibling in node.parent.named_children:
                                parts = sibling.named_children
                                if (
                                    sibling.type == "attribute"
                                    and len(parts) > 1
                                    and raw(parts[0]).lower() in ("name", "id", "type")
                                ):
                                    related_sensitive |= sensitive_key(raw(parts[-1]))
                        add(
                            a,
                            b,
                            attribute_codec,
                            force=sensitive_key(key) or related_sensitive,
                        )
                covered.append((start, end))
            elif node.type in ("text", "plain_value", "string_value") and language in (
                "html",
                "css",
            ):
                if node.type == "string_value" and text[start : start + 1] in (
                    '"',
                    "'",
                ):
                    add(
                        start + 1,
                        end - 1,
                        "js-double" if text[start] == '"' else "js-single",
                    )
                else:
                    add_plain_matches(
                        start, end, "html-text" if language == "html" else "plain"
                    )
                covered.append((start, end))
        # Findings outside understood contexts are never silently treated as safe.
        for a, b, kind in detect(text, values, patterns):
            if not any(x <= a and b <= y for x, y in covered):
                issue(a, "unhandled-" + kind)
    else:
        add_plain_matches(0, len(text))
    # Choose the widest range for nested matches; reject crossing intervals.
    selected = []
    for edit in sorted(result.edits, key=lambda r: (r.start, -r.end)):
        if selected and edit.start < selected[-1].end:
            if edit.end <= selected[-1].end:
                continue
            issue(edit.start, "overlapping-detections")
            continue
        selected.append(edit)
    result.edits = selected
    return result
