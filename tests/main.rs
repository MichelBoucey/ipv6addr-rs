//! Integration tests ported from the original test suite of the
//! `Text.IPv6Addr` library: `tests/Main.hs`.
//!
//! Each test below corresponds to an assertion of the Haskell `tests` list.
//! Like the Haskell `Eq` instance (which compares addresses through
//! `toIPv6`), the assertions compare by address value: the canonical
//! `Ipv6Addr` equality.
//!
//! The suite does not cover `toHostName`, `toIPv6`, the JSON instances or
//! the OS network-interfaces functions, none of which are part of this
//! port.

use ipv6addr::{
    Ipv6Addr, Ipv6AddrToken, Ipv6AddrTokens, full_ipv6_addr, ipv6_addr,
    mac_addr_to_ipv6_addr_tokens, pure_ipv6_addr, to_ip6_arpa, to_unc,
};

/// Asserts `ipv6_addr` on one input, by address value.
fn check_ipv6_addr(input: &str, expected: Option<&str>) {
    match expected {
        Some(text) => assert_eq!(
            ipv6_addr(input),
            Some(Ipv6Addr::from(text)),
            "maybeIPv6Addr {input:?}"
        ),
        None => assert_eq!(ipv6_addr(input), None, "maybeIPv6Addr {input:?}"),
    }
}

/// Asserts `pure_ipv6_addr` on one input, by address value.
fn check_pure_ipv6_addr(input: &str, expected: Option<&str>) {
    match expected {
        Some(text) => assert_eq!(
            pure_ipv6_addr(input),
            Some(Ipv6Addr::from(text)),
            "maybePureIPv6Addr {input:?}"
        ),
        None => assert_eq!(pure_ipv6_addr(input), None, "maybePureIPv6Addr {input:?}"),
    }
}

/// Asserts `full_ipv6_addr` on one input, by address value.
fn check_full_ipv6_addr(input: &str, expected: Option<&str>) {
    match expected {
        Some(text) => assert_eq!(
            full_ipv6_addr(input),
            Some(Ipv6Addr::from(text)),
            "maybeFullIPv6Addr {input:?}"
        ),
        None => assert_eq!(full_ipv6_addr(input), None, "maybeFullIPv6Addr {input:?}"),
    }
}

/// Asserts `to_ip6_arpa` on one input.
fn check_ip6_arpa(input: &str, expected: &str) {
    assert_eq!(
        to_ip6_arpa(&Ipv6Addr::from(input)).as_deref(),
        Some(expected),
        "toIP6ARPA {input:?}"
    );
}

#[test]
fn ipv6_addr_trivial_forms() {
    for (input, expected) in [
        (":", None),
        ("::", Some("::")),
        (":::", None),
        ("::::", None),
        ("::df0::", None),
        ("0:0:0:0:0:0:0", None),
        ("0:0:0:0:0:0:0:0", Some("::")),
        ("0:0:0:0:0:0:0:0:0", None),
        ("1", None),
        ("::1", Some("::1")),
        (":::1", None),
        ("::1:", None),
        ("0000:0000:0000:0000:0000:0000:0000:0001", Some("::1")),
        ("0:0:0:0:0:0:0:1", Some("::1")),
        ("fe80", None),
        ("fe80::", Some("fe80::")),
    ] {
        check_ipv6_addr(input, expected);
    }
}

#[test]
fn ipv6_addr_single_hextet_forms() {
    for (input, expected) in [
        ("a", None),
        ("ab", None),
        ("abc", None),
        ("abcd", None),
        ("abcd:", None),
        ("abcd::", Some("abcd::")),
        ("abcd:::", None),
        ("abcde::", None),
        ("a::", Some("a::")),
        ("0a::", Some("a::")),
        ("00a::", Some("a::")),
        ("000a::", Some("a::")),
        ("0000a::", None),
        ("adb6", None),
        ("adb6ce67", None),
        ("adb6:ce67", None),
        ("adb6::ce67", Some("adb6::ce67")),
    ] {
        check_ipv6_addr(input, expected);
    }
}

#[test]
fn ipv6_addr_embedded_ipv4_forms() {
    for (input, expected) in [
        ("::1.2.3.4", Some("::1.2.3.4")),
        ("::ffff:1.2.3.4", Some("::ffff:1.2.3.4")),
        ("::ffff:0:1.2.3.4", Some("::ffff:0:1.2.3.4")),
        ("64:ff9b::1.2.3.4", Some("64:ff9b::1.2.3.4")),
        ("fe80::5efe:1.2.3.4", Some("fe80::5efe:1.2.3.4")),
        ("0:0:0:0:0:ffff:192.0.2.1", Some("::ffff:192.0.2.1")),
        ("::192.0.2.1", Some("::192.0.2.1")),
        ("192.0.2.1::", None),
        ("::ffff:192.0.2.1", Some("::ffff:192.0.2.1")),
    ] {
        check_ipv6_addr(input, expected);
    }
}

#[test]
fn ipv6_addr_full_length_forms() {
    for (input, expected) in [
        (
            "FE80:CD00:0000:0CDE:1257:0000:211E:729C",
            Some("fe80:cd00:0:cde:1257:0:211e:729c"),
        ),
        ("FE80:CD00:0000:0CDE:1257:0000:211E:729X", None),
        ("FE80:CD00:0000:0CDE:1257:0000:211E:729CX", None),
        ("FE80:CD00:0000:0CDE:0000:211E:729C", None),
        ("FE80:CD00:0000:0CDE:FFFF:1257:0000:211E:729C", None),
        (
            "1111:2222:3333:4444:5555:6666:7777:8888",
            Some("1111:2222:3333:4444:5555:6666:7777:8888"),
        ),
        (":1111:2222:3333:4444:5555:6666:7777:8888", None),
        ("1111:2222:3333:4444:5555:6666:7777:8888:", None),
        ("1111::3333:4444:5555:6666::8888", None),
        (
            "AAAA:BBBB:CCCC:DDDD:EEEE:FFFF:0000:0000",
            Some("aaaa:bbbb:cccc:dddd:eeee:ffff::"),
        ),
        (
            "2001:db8:aaaa:bbbb:cccc:dddd:eeee:0001",
            Some("2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"),
        ),
        (
            "2001:db8:aaaa:bbbb:cccc:dddd:eeee:001",
            Some("2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"),
        ),
        (
            "2001:db8:aaaa:bbbb:cccc:dddd:eeee:01",
            Some("2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"),
        ),
        (
            "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1",
            Some("2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"),
        ),
        (
            "2001:db8:aaaa:bbbb:cccc:dddd::1",
            Some("2001:db8:aaaa:bbbb:cccc:dddd:0:1"),
        ),
        (
            "2001:db8:aaaa:bbbb:cccc:dddd:0:1",
            Some("2001:db8:aaaa:bbbb:cccc:dddd:0:1"),
        ),
    ] {
        check_ipv6_addr(input, expected);
    }
}

#[test]
fn ipv6_addr_hextet_compression() {
    for (input, expected) in [
        ("2001:db8:0:0:1:0:0:1", Some("2001:db8::1:0:0:1")),
        ("2001:db8:0:1:0:0:0:1", Some("2001:db8:0:1::1")),
        ("2001:DB8:0:0:0::1", Some("2001:db8::1")),
        ("2001:0DB8:0:0::1", Some("2001:db8::1")),
        ("2001:0dB8:0::1", Some("2001:db8::1")),
        ("2001:db8::1", Some("2001:db8::1")),
        ("2001:db8:0:1::1", Some("2001:db8:0:1::1")),
        ("2001:0db8:0:1:0:0:0:1", Some("2001:db8:0:1::1")),
        ("2001:DB8::1:1:1:1:1", Some("2001:db8:0:1:1:1:1:1")),
        ("2001:DB8::1:1:0:1:1", Some("2001:db8:0:1:1:0:1:1")),
        ("fe80:0:0:0:0:0:0:0", Some("fe80::")),
        ("fe80:0000:0000:0000:0000:0000:0000:0000", Some("fe80::")),
        ("2001:db8:Bad:0:0::0:1", Some("2001:db8:bad::1")),
        ("2001:0:0:1:b:0:0:A", Some("2001::1:b:0:0:a")),
        ("2001:0:0:1:000B:0:0:0", Some("2001:0:0:1:b::")),
        (
            "2001:0DB8:85A3:0000:0000:8A2E:0370:7334",
            Some("2001:db8:85a3::8a2e:370:7334"),
        ),
    ] {
        check_ipv6_addr(input, expected);
    }
}

#[test]
fn pure_ipv6_addr_always_rewrites_an_embedded_ipv4() {
    for (input, expected) in [
        ("0:0:0:0:0:ffff:192.0.2.1", Some("::ffff:c000:201")),
        ("::ffff:192.0.2.1", Some("::ffff:c000:201")),
    ] {
        check_pure_ipv6_addr(input, expected);
    }
}

#[test]
fn full_ipv6_addr_expands_every_chunk() {
    for (input, expected) in [
        ("::", Some("0000:0000:0000:0000:0000:0000:0000:0000")),
        (
            "0:0:0:0:0:0:0:0",
            Some("0000:0000:0000:0000:0000:0000:0000:0000"),
        ),
        ("::1", Some("0000:0000:0000:0000:0000:0000:0000:0001")),
        (
            "2001:db8::1",
            Some("2001:0db8:0000:0000:0000:0000:0000:0001"),
        ),
        (
            "a:bb:ccc:dddd:1cDc::1",
            Some("000a:00bb:0ccc:dddd:1cdc:0000:0000:0001"),
        ),
        (
            "FE80::0202:B3FF:FE1E:8329",
            Some("fe80:0000:0000:0000:0202:b3ff:fe1e:8329"),
        ),
        (
            "aDb6::CE67",
            Some("adb6:0000:0000:0000:0000:0000:0000:ce67"),
        ),
    ] {
        check_full_ipv6_addr(input, expected);
    }
}

#[test]
fn to_ip6_arpa_returns_the_reverse_dns_name() {
    check_ip6_arpa(
        "::1",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.IP6.ARPA.",
    );
    check_ip6_arpa(
        "2b02:0b08:0:7::0001",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.0.0.0.0.0.0.0.8.0.b.0.2.0.b.2.IP6.ARPA.",
    );
    check_ip6_arpa(
        "2b02:b08:0:7::1",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.0.0.0.0.0.0.0.8.0.b.0.2.0.b.2.IP6.ARPA.",
    );
    check_ip6_arpa(
        "fdda:5cc1:23:4::1f",
        "f.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4.0.0.0.3.2.0.0.1.c.c.5.a.d.d.f.IP6.ARPA.",
    );
    check_ip6_arpa(
        "2001:db8::",
        "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.IP6.ARPA.",
    );
    check_ip6_arpa(
        "4321:0:1:2:3:4:567:89ab",
        "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.IP6.ARPA.",
    );
}

#[test]
fn to_unc_returns_the_windows_unc_path() {
    assert_eq!(
        to_unc(&Ipv6Addr::from("2001:0DB8:002a:1005:230:48ff:FE73:989d")).as_deref(),
        Some("2001-db8-2a-1005-230-48ff-fe73-989d.ipv6-literal.net")
    );
    assert_eq!(
        to_unc(&Ipv6Addr::from("2001:0db8:85a3:0000:0000:8a2e:0370:7334")).as_deref(),
        Some("2001-db8-85a3--8a2e-370-7334.ipv6-literal.net")
    );
}

#[test]
fn mac_addr_to_ipv6_addr_tokens_splits_the_three_16_bit_chunks() {
    let expected: Ipv6AddrTokens = [
        Ipv6AddrToken::SixteenBit(String::from("fa1d")),
        Ipv6AddrToken::Colon,
        Ipv6AddrToken::SixteenBit(String::from("58cc")),
        Ipv6AddrToken::Colon,
        Ipv6AddrToken::SixteenBit(String::from("9516")),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        mac_addr_to_ipv6_addr_tokens("fa:1d:58:cc:95:16"),
        Some(expected)
    );
}
