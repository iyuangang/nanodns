"""
Unit tests for nanodns.protocol
Covers: name encoding/decoding, all rdata encoders, message parse/build roundtrips.
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nanodns.protocol import (
    DNSMessage, DNSQuestion, DNSRecord,
    QType, QClass,
    encode_name, decode_name,
    encode_a, encode_aaaa, encode_cname, encode_txt,
    encode_mx, encode_ns, encode_ptr, encode_soa,
    parse_message, build_message,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Name encoding / decoding
# ═══════════════════════════════════════════════════════════════════════════════

class TestNameEncoding:

    def test_multi_label_roundtrip(self):
        enc = encode_name("web.internal.lan")
        dec, _ = decode_name(enc, 0)
        assert dec == "web.internal.lan"

    def test_root(self):
        assert encode_name(".") == b"\x00"

    def test_trailing_dot_stripped(self):
        assert encode_name("example.com") == encode_name("example.com.")

    def test_single_label_roundtrip(self):
        enc = encode_name("localhost")
        dec, _ = decode_name(enc, 0)
        assert dec == "localhost"

    def test_decode_with_prefix_offset(self):
        data = b"\x00" * 4 + encode_name("foo.bar")
        name, _ = decode_name(data, 4)
        assert name == "foo.bar"

    def test_decode_compression_pointer(self):
        # "example.com" at offset 0, then a pointer back to it
        suffix = encode_name("example.com")
        data = suffix + b"\x03sub" + b"\xc0\x00"
        name, _ = decode_name(data, len(suffix))
        assert name == "sub.example.com"


# ═══════════════════════════════════════════════════════════════════════════════
# rdata encoders
# ═══════════════════════════════════════════════════════════════════════════════

class TestRdataEncoders:

    def test_encode_a_values(self):
        assert encode_a("192.168.1.1") == b"\xc0\xa8\x01\x01"
        assert encode_a("0.0.0.0")     == b"\x00\x00\x00\x00"
        assert encode_a("255.255.255.255") == b"\xff\xff\xff\xff"

    def test_encode_aaaa_loopback(self):
        data = encode_aaaa("::1")
        assert len(data) == 16 and data[-1] == 1

    def test_encode_aaaa_full(self):
        assert len(encode_aaaa("2001:db8::1")) == 16

    def test_encode_txt_normal(self):
        assert encode_txt("hello") == b"\x05hello"

    def test_encode_txt_empty(self):
        assert encode_txt("") == b"\x00"

    def test_encode_txt_long(self):
        data = encode_txt("x" * 200)
        assert data[0] == 200

    def test_encode_mx_priority_zero(self):
        assert encode_mx(0, "mail.example.com")[:2] == b"\x00\x00"

    def test_encode_mx_priority_20(self):
        assert encode_mx(20, "mail.example.com")[:2] == b"\x00\x14"

    def test_encode_soa_produces_bytes(self):
        data = encode_soa("ns1.t.lan", "admin.t.lan", 1, 3600, 900, 604800, 300)
        assert len(data) > 20

    def test_encode_ptr_roundtrip(self):
        name, _ = decode_name(encode_ptr("web.test.lan"), 0)
        assert name == "web.test.lan"

    def test_encode_ns_roundtrip(self):
        name, _ = decode_name(encode_ns("ns1.test.lan"), 0)
        assert name == "ns1.test.lan"

    def test_encode_cname_roundtrip(self):
        name, _ = decode_name(encode_cname("target.test.lan"), 0)
        assert name == "target.test.lan"


# ═══════════════════════════════════════════════════════════════════════════════
# DNSRecord / DNSQuestion helpers
# ═══════════════════════════════════════════════════════════════════════════════

class TestDNSDataTypes:

    def test_record_rtype_name_known(self):
        assert DNSRecord("x", QType.A, QClass.IN, 300, b"").rtype_name == "A"

    def test_record_rtype_name_unknown(self):
        assert DNSRecord("x", 999, QClass.IN, 300, b"").rtype_name == "TYPE999"

    def test_question_qtype_name_known(self):
        assert DNSQuestion("x", QType.AAAA, QClass.IN).qtype_name == "AAAA"
        assert DNSQuestion("x", QType.MX,   QClass.IN).qtype_name == "MX"

    def test_question_qtype_name_unknown(self):
        assert DNSQuestion("x", 9999, QClass.IN).qtype_name == "TYPE9999"


# ═══════════════════════════════════════════════════════════════════════════════
# Message parsing and building
# ═══════════════════════════════════════════════════════════════════════════════

class TestMessageParsing:

    def test_query_roundtrip(self):
        msg = DNSMessage(msg_id=1, flags=0x0100)
        msg.questions.append(DNSQuestion("example.com", QType.A, QClass.IN))
        parsed = parse_message(build_message(msg))
        assert parsed.msg_id == 1
        assert parsed.questions[0].name == "example.com"
        assert parsed.questions[0].qtype == QType.A

    def test_response_flag(self):
        msg = DNSMessage(msg_id=1, flags=0x8180)
        assert msg.is_response and not msg.is_query

    def test_query_flag(self):
        msg = DNSMessage(msg_id=1, flags=0x0100)
        assert msg.is_query and not msg.is_response

    def test_rcode_noerror(self):
        assert DNSMessage(1, 0x8180).rcode == 0

    def test_rcode_nxdomain(self):
        assert DNSMessage(1, 0x8183).rcode == 3

    def test_set_rcode(self):
        msg = DNSMessage(1, 0x8180)
        msg.set_rcode(3);  assert msg.rcode == 3
        msg.set_rcode(0);  assert msg.rcode == 0

    def test_set_rcode_preserves_other_flags(self):
        msg = DNSMessage(1, 0x8580)
        msg.set_rcode(2)
        assert msg.rcode == 2
        assert msg.flags & 0xFFF0 == 0x8580

    def test_parse_too_short_raises(self):
        with pytest.raises(Exception):
            parse_message(b"\x00\x01")

    def test_parse_empty_raises(self):
        with pytest.raises(Exception):
            parse_message(b"")

    def test_multiple_questions_roundtrip(self):
        msg = DNSMessage(msg_id=7, flags=0x0100)
        msg.questions.append(DNSQuestion("a.com", QType.A,    QClass.IN))
        msg.questions.append(DNSQuestion("b.com", QType.AAAA, QClass.IN))
        parsed = parse_message(build_message(msg))
        assert len(parsed.questions) == 2
        assert parsed.questions[1].name == "b.com"

    def test_response_with_answer_roundtrip(self):
        msg = DNSMessage(msg_id=5, flags=0x8180)
        msg.questions.append(DNSQuestion("web.test.lan", QType.A, QClass.IN))
        msg.answers.append(
            DNSRecord("web.test.lan", QType.A, QClass.IN, 300, encode_a("10.0.0.1"))
        )
        parsed = parse_message(build_message(msg))
        assert parsed.answers[0].rdata == encode_a("10.0.0.1")
        assert parsed.answers[0].ttl == 300

    def test_authority_and_additional_sections(self):
        msg = DNSMessage(msg_id=1, flags=0x8180)
        msg.authority.append(
            DNSRecord("test.lan", QType.NS, QClass.IN, 300, encode_ns("ns1.test.lan"))
        )
        msg.additional.append(
            DNSRecord("ns1.test.lan", QType.A, QClass.IN, 300, encode_a("1.2.3.4"))
        )
        parsed = parse_message(build_message(msg))
        assert len(parsed.authority)   == 1
        assert len(parsed.additional) == 1
