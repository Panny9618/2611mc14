import hashlib
import unicodedata

import pytest

from hashlab.canonical import CanonicalJSONError, canonical_digest, canonicalize


def c(s: str | bytes) -> bytes:
    return canonicalize(s.encode("utf-8") if isinstance(s, str) else s)


def test_key_order_and_whitespace_do_not_matter():
    a = '{"from":"Alice","to":"Bob","amount":10}'
    b = '{\n  "amount" : 10,\n\t"to": "Bob",  "from":"Alice"\r\n}\n'
    assert c(a) == c(b) == b'{"amount":10,"from":"Alice","to":"Bob"}'


def test_nested_objects_sorted_arrays_kept():
    assert c('{"z":[3,1,2],"a":{"y":false,"x":null}}') == b'{"a":{"x":null,"y":false},"z":[3,1,2]}'


def test_keys_sorted_by_code_point():
    # 'B' (0x42) < 'a' (0x61) < 'é' (0xE9)
    assert c('{"é":1,"a":2,"B":3}') == '{"B":3,"a":2,"é":1}'.encode("utf-8")


def test_utf8_not_escaped_and_ascii_escapes_resolved():
    assert c('{"name":"caf\\u00e9"}') == c('{"name":"café"}') == '{"name":"café"}'.encode()


def test_control_characters_escaped():
    assert c('{"m":"a\\nb\\u0001"}') == b'{"m":"a\\nb\\u0001"}'


def test_integer_vs_string_differ():
    assert c('{"amount":10}') != c('{"amount":"10"}')


def test_nfc_nfd_not_normalised():
    nfc = unicodedata.normalize("NFC", "café")
    nfd = unicodedata.normalize("NFD", "café")
    assert c('{"n":"%s"}' % nfc) != c('{"n":"%s"}' % nfd)


def test_big_integers_and_negative_zero():
    assert c('{"a":123456789012345678901234567890,"b":-0}') == b'{"a":123456789012345678901234567890,"b":0}'


def test_known_digest():
    canon, d = canonical_digest(b'{"b":1,"a":2}')
    assert canon == b'{"a":2,"b":1}'
    assert d.hex == hashlib.sha256(b'{"a":2,"b":1}').hexdigest()


def test_idempotent():
    once = c('{"b":[{"d":1,"c":2}],"a":"x"}')
    assert canonicalize(once) == once


@pytest.mark.parametrize("bad,rule", [
    ('{"a":1.5}', "R4"), ('{"a":1.0}', "R4"), ('{"a":1e3}', "R4"),
    ('{"a":NaN}', "R4"), ('{"a":Infinity}', "R4"),
    ('{"a":1,"a":2}', "R3"), ('{"x":{"a":1,"a":1}}', "R3"),
    ('[1,2]', "R2"), ('"str"', "R2"), ('5', "R2"),
    ('{"a":"\\ud800"}', "R9"),
    ('{"a":1', "invalid JSON"), ('', "invalid JSON"),
])
def test_rejections(bad, rule):
    with pytest.raises(CanonicalJSONError, match=rule):
        c(bad)


def test_bom_rejected():
    with pytest.raises(CanonicalJSONError, match="R1"):
        c(b'\xef\xbb\xbf{"a":1}')


def test_invalid_utf8_rejected():
    with pytest.raises(CanonicalJSONError, match="R1"):
        c(b'{"a":"\xff"}')
