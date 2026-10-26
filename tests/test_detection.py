import pytest
from web_sanitizer.detect import detect, sensitive_key
from web_sanitizer.codecs import decode_value, encode_value


@pytest.mark.parametrize(
    "key",
    [
        "db_password",
        "apiKey",
        "SMTPHost",
        "username",
        "client_secret",
        "Authorization",
        "accessToken",
        "DB_USER",
        "private_key",
        "email",
        "passwd",
        "pwd",
    ],
)
def test_sensitive_names(key):
    assert sensitive_key(key)


@pytest.mark.parametrize(
    "key",
    [
        "password_length",
        "token_count",
        "user_agent",
        "hostname_label",
        "password_enabled",
        "max_users",
    ],
)
def test_control_names_not_secrets(key):
    assert not sensitive_key(key)


@pytest.mark.parametrize(
    "value",
    [
        "person@company.de",
        "192.168.1.2",
        "2001:db8::1",
        "https://intranet.example.org/a",
        "ghp_" + "a" * 36,
        "AKIA" + "A" * 16,
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
        "Bearer abcdefghijklmnopqrstuvwxyz123456",
    ],
)
def test_patterns(value):
    assert detect(value)


@pytest.mark.parametrize(
    "codec,value",
    [
        ("php-single", "a'b\\c"),
        ("php-double", 'a"$b\\c\n'),
        ("js-double", 'a"b\\c\n'),
        ("js-template", "a`${b}\\c\n"),
        ("json", 'ü"\\\n'),
        ("plain", "hi"),
    ],
)
def test_codecs_roundtrip(codec, value):
    assert decode_value(encode_value(value, codec), codec) == value


def test_php_double_quote_escape_semantics():
    assert decode_value(r"\b\'", "php-double") == r"\b\'"


@pytest.mark.parametrize(
    "value",
    [
        "+49 176 12345678",
        "4111 1111 1111 1111",
        "DE89370400440532013000",
        "dckr_pat_" + "a" * 30,
    ],
)
def test_additional_sensitive_formats(value):
    assert detect(value)
