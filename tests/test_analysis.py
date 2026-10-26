import pytest
from web_sanitizer.analysis import analyze


@pytest.mark.parametrize(
    "name,source,secrets",
    [
        (
            "x.php",
            '<?php $password="weak"; $a=["host"=>"db01", "user"=>"root"]; define("DB_PASSWORD","abc"); new PDO("mysql:host=db02", "admin", "xyz");',
            ["weak", "db01", "root", "abc", "mysql:host=db02", "admin", "xyz"],
        ),
        (
            "x.js",
            'const c = {auth: {password: "weak"}, apiKey: "abc"}; let userName = "max";',
            ["weak", "abc", "max"],
        ),
        ("x.ts", 'const secret: string = "abc";', ["abc"]),
        ("x.json", '{"password":"abc","port":3306,"debug":false}', ["abc"]),
        (
            "x.html",
            '<script>const password="abc";</script><a href="https://internal.example.org">Hi</a>',
            ["abc", "https://internal.example.org"],
        ),
        (
            "x.php",
            '<script>const password="abc";</script><?php $user="max";',
            ["abc", "max"],
        ),
        (
            ".env",
            'PORT=3306\r\nDEBUG=false\r\nPASSWORD="abc"\r\n',
            ["3306", "false", "abc"],
        ),
        ("x.ini", "[db]\nuser=root\nport=3306\n", ["root", "3306"]),
    ],
)
def test_structure(name, source, secrets):
    result = analyze(name, source, {})
    assert not result.issues, result.issues
    found = [x.value for x in result.edits]
    for secret in secrets:
        assert secret in found


@pytest.mark.parametrize(
    "name,source",
    [
        ("x.php", '<?php $password = "prefix" . getSecret();'),
        ("x.js", "const password = `prefix${x}`;"),
        ("x.js", "const password = lookup();"),
        ("x.php", "<?php $password = 1234;"),
        ("x.js", "const password = ;"),
    ],
)
def test_unsafe_expressions_block(name, source):
    assert analyze(name, source, {}).issues


def test_keys_remain_intact():
    source = 'const c = {password: "abc", password_length: 12};'
    result = analyze("x.js", source, {})
    assert [x.value for x in result.edits] == ["abc"]


def test_escaped_secret_decoded():
    result = analyze("x.js", r'const password="a\"b\\c";', {})
    assert result.edits[0].value == 'a"b\\c'


def test_known_values_do_not_rewrite_structure_keys():
    result = analyze("x.php", '<?php $user="user"; $c=["user"=>"user"];', {}, ["user"])
    assert result.issues
    assert not any(r.start <= 28 < r.end for r in result.edits)


def test_known_values_propagate_inside_literals():
    result = analyze("x.js", 'const x="rooted"; const y="abc";', {}, ["abc", "root"])
    assert {r.value for r in result.edits} == {"abc", "rooted"}


def test_unknown_key_provider_token_still_found():
    secret = "ghp_" + "A" * 36
    assert analyze("x.js", f'let x="{secret}";', {}).edits


def test_secret_in_css_url():
    assert analyze(
        "x.css", "body { background: url(https://host.example.org/image.png); }", {}
    ).edits


def test_simple_variable_flow():
    result = analyze("x.php", '<?php $x="abc"; $password=$x;', {})
    assert not result.issues
    assert [r.value for r in result.edits] == ["abc"]


def test_serialized_credentials_block():
    assert analyze("x.js", """const data='{"password":"abc"}';""", {}).issues


def test_dynamic_eval_block():
    assert analyze("x.js", "eval(code);", {}).issues


def test_nested_database_object_not_blocked():
    result = analyze(
        "x.php",
        """<?php $config=['database'=>['host'=>'db01','username'=>'admin','password'=>'abc','port'=>3306],'debug'=>false];""",
        {},
    )
    assert not result.issues
    assert {"db01", "admin", "abc"} <= {r.value for r in result.edits}


def test_short_password_also_detected_in_comment():
    result = analyze("x.js", "// use abc here\nconst x=1;", {}, ["abc"])
    assert any(r.value == "abc" for r in result.edits)


def test_block_comment_closer_retained():
    text = "<?php /* password=abc */ $x=1;"
    result = analyze("x.php", text, {})
    assert [r.value for r in result.edits] == ["abc"]


def test_html_sensitive_input_and_meta():
    result = analyze(
        "x.html",
        '<input name="password" value="abc"><meta name="csrf-token" content="xyz">',
        {},
    )
    assert {r.value for r in result.edits} == {"abc", "xyz"}


def test_php_class_property():
    result = analyze("x.php", '<?php class X { private $password="abc"; }', {})
    assert not result.issues
    assert [r.value for r in result.edits] == ["abc"]


def test_unicode_offsets_are_exact():
    text = '<?php /* Café 😀 */ $password="hello";'
    result = analyze("x.php", text, {})
    assert len(result.edits) == 1
    assert text[result.edits[0].start : result.edits[0].end] == "hello"
