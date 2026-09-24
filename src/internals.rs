//! Internal functions for tokenizing, validating and rewriting IPv6 addresses.
//!
//! Token lists are stored in a [`SmallVec`] (`crate::types::Ipv6AddrTokens`)
//! and functions return an [`Option`] whenever the original design relied on a
//! `Maybe`.
//!
//! The functions are consumed by the public API in `crate::functions` and by
//! the canonical `Ipv6Addr` equality in `crate::types`.

use crate::types::{Ipv6Addr, Ipv6AddrToken, Ipv6AddrTokens};
use itertools::Itertools;
use smallvec::SmallVec;

/// Returns the corresponding text of a list of IPv6 address tokens.
///
/// Given an arbitrary list of IPv6 address tokens, returns the
/// corresponding text.
pub(crate) fn ipv6_tokens_to_text(tks: &Ipv6AddrTokens) -> String {
    tks.iter().map(ipv6_token_to_text).collect()
}

/// Returns the corresponding text of an IPv6 address token.
pub(crate) fn ipv6_token_to_text(token: &Ipv6AddrToken) -> &str {
    match token {
        Ipv6AddrToken::SixteenBit(s) => s,
        Ipv6AddrToken::Colon => ":",
        Ipv6AddrToken::DoubleColon => "::",
        // "A single 16-bit 0000 field MUST be represented as 0" (RFC 5952, 4.1)
        Ipv6AddrToken::AllZeros => "0",
        Ipv6AddrToken::Ipv4Addr(a) => a,
    }
}

/// Returns `true` if a list of IPv6 address tokens constitutes a valid
/// IPv6 address.
pub(crate) fn is_ipv6_addr(tks: &Ipv6AddrTokens) -> bool {
    // [] -> False
    if tks.is_empty() {
        return false;
    }
    // [DoubleColon] -> True
    if tks.len() == 1 && matches!(tks[0], Ipv6AddrToken::DoubleColon) {
        return true;
    }
    // [DoubleColon, SixteenBit "1"] -> True
    if tks.len() == 2
        && matches!(tks[0], Ipv6AddrToken::DoubleColon)
        && matches!(&tks[1], Ipv6AddrToken::SixteenBit(s) if s == "1")
    {
        return true;
    }

    if !diff_next(tks) {
        return false;
    }

    let cdctks = count_double_colon(tks);
    let lentks = tks.len();
    let Some(lasttk) = tks.last() else {
        return false;
    };
    let lenconst = (lentks == 15 && cdctks == 0) || (lentks < 15 && cdctks == 1);

    // The first token has to be a SixteenBit, a DoubleColon or an AllZeros chunk.
    let first_valid = matches!(
        tks[0],
        Ipv6AddrToken::SixteenBit(_) | Ipv6AddrToken::DoubleColon | Ipv6AddrToken::AllZeros
    );
    if !first_valid {
        return false;
    }

    match count_ipv4_addr(tks) {
        0 => {
            matches!(
                lasttk,
                Ipv6AddrToken::SixteenBit(_) | Ipv6AddrToken::DoubleColon | Ipv6AddrToken::AllZeros
            ) && lenconst
        }
        1 => {
            matches!(lasttk, Ipv6AddrToken::Ipv4Addr(_))
                && ((lentks == 13 && cdctks == 0) || (lentks < 12 && cdctks == 1))
        }
        _ => false,
    }
}

/// Returns `false` when two consecutive tokens are not allowed
/// (`DoubleColon` followed by `Colon`, or two chunks in a row), `true`
/// otherwise.
fn diff_next(tks: &Ipv6AddrTokens) -> bool {
    // [] -> False
    if tks.is_empty() {
        return false;
    }
    // [_] -> True
    if tks.len() == 1 {
        return true;
    }
    let mut i = 0;
    while i + 1 < tks.len() {
        let t = &tks[i];
        let h = &tks[i + 1];
        match t {
            Ipv6AddrToken::DoubleColon => return !matches!(h, Ipv6AddrToken::Colon),
            Ipv6AddrToken::SixteenBit(_) | Ipv6AddrToken::AllZeros => {
                if matches!(h, Ipv6AddrToken::SixteenBit(_) | Ipv6AddrToken::AllZeros) {
                    return false;
                }
            }
            // Colon and IPv4Addr tokens are transparent: keep scanning.
            _ => {}
        }
        i += 1;
    }
    true
}

/// Returns the number of `DoubleColon` tokens in the list.
fn count_double_colon(tks: &Ipv6AddrTokens) -> usize {
    tks.iter()
        .filter(|t| matches!(t, Ipv6AddrToken::DoubleColon))
        .count()
}

/// Returns the number of embedded IPv4 address tokens in the list.
pub(crate) fn count_ipv4_addr(tks: &Ipv6AddrTokens) -> usize {
    tks.iter()
        .filter(|t| matches!(t, Ipv6AddrToken::Ipv4Addr(_)))
        .count()
}

/// Returns the tokenized list of a canonized IPv6 address text
/// representation, validated against RFC 4291 and canonized in
/// conformation with RFC 5952, or `None`.
///
/// An embedded IPv4 address is kept in its text representation when the
/// address belongs to a well-known IPv4/IPv6 transition prefix
/// (RFC 5952 Section 5), otherwise it is rewritten to hexadecimal digits.
pub(crate) fn tok_ipv6_addr(text: &str) -> Option<Ipv6AddrTokens> {
    let tks = ipv6_addr_tokens(text)?;
    if !is_ipv6_addr(&tks) {
        return None;
    }
    let tks = to_double_colon(&from_double_colon(&tks));
    let tks = if ipv4_addr_rewrite(&tks) {
        let (last, init) = tks.split_last()?;
        let mut out = Ipv6AddrTokens::new();
        out.extend(init.iter().cloned());
        out.extend(ipv4_addr_to_ipv6_addr_tokens(last));
        out
    } else {
        tks
    };
    Some(tks)
}

/// Returns the tokenized list of a canonized pure IPv6 address text
/// representation, always rewriting an embedded IPv4 address if present,
/// or `None`.
pub(crate) fn tok_pure_ipv6_addr(text: &str) -> Option<Ipv6AddrTokens> {
    let tks = ipv6_addr_tokens(text)?;
    if !is_ipv6_addr(&tks) {
        return None;
    }
    // Always replace the embedded IPv4 address, if any.
    let tks = from_double_colon(&tks);
    let tks = match tks.split_last() {
        Some((last, init)) => {
            let mut out = Ipv6AddrTokens::new();
            out.extend(init.iter().cloned());
            out.extend(ipv4_addr_to_ipv6_addr_tokens(last));
            out
        }
        None => return None,
    };
    Some(to_double_colon(&tks))
}

/// Tokenizes a text into a list of IPv6 address tokens, or returns `None`.
///
/// The whole text has to be consumed: a partial tokenization is a failure.
pub(crate) fn ipv6_addr_tokens(text: &str) -> Option<Ipv6AddrTokens> {
    if text.is_empty() {
        return None;
    }
    let mut tks = Ipv6AddrTokens::new();
    let mut rest = text;
    while !rest.is_empty() {
        // ipv4Addr <|> sixteenBit <|> doubleColon <|> colon
        if let Some((t, r)) = parse_ipv4_addr(rest) {
            tks.push(t);
            rest = r;
            continue;
        }
        if let Some((t, r)) = parse_sixteen_bit(rest) {
            tks.push(t);
            rest = r;
            continue;
        }
        if let Some((t, r)) = parse_double_colon(rest) {
            tks.push(t);
            rest = r;
            continue;
        }
        if let Some((t, r)) = parse_colon(rest) {
            tks.push(t);
            rest = r;
            continue;
        }
        return None;
    }
    Some(tks)
}

/// Returns `true` when the embedded IPv4 address has to be rewritten to
/// hexadecimal digits: i.e. when it does **not** stand for a well-known
/// IPv4/IPv6 transition prefix (RFC 5952 Section 5).
///
/// The prefix addresses keep their IPv4 text representation:
///
/// IPv4-compatible IPv6 address like "::1.2.3.4"
///
/// IPv4-mapped IPv6 address like "::ffff:1.2.3.4"
///
/// IPv4-translated address like "::ffff:0:1.2.3.4"
///
/// IPv4-translatable address like "64:ff9b::1.2.3.4"
///
/// ISATAP address like "fe80::5efe:1.2.3.4"
fn ipv4_addr_rewrite(tks: &Ipv6AddrTokens) -> bool {
    if !matches!(tks.last(), Some(Ipv6AddrToken::Ipv4Addr(_))) {
        return false;
    }
    let itks = &tks[..tks.len() - 1];
    let is_transition_prefix = matches!(itks, [Ipv6AddrToken::DoubleColon])
        || matches!(
            itks,
            [Ipv6AddrToken::DoubleColon, Ipv6AddrToken::SixteenBit(s), Ipv6AddrToken::Colon]
                if s == "ffff"
        )
        || matches!(
            itks,
            [
                Ipv6AddrToken::DoubleColon,
                Ipv6AddrToken::SixteenBit(s),
                Ipv6AddrToken::Colon,
                Ipv6AddrToken::AllZeros,
                Ipv6AddrToken::Colon,
            ] if s == "ffff"
        )
        || matches!(
            itks,
            [
                Ipv6AddrToken::SixteenBit(a),
                Ipv6AddrToken::Colon,
                Ipv6AddrToken::SixteenBit(b),
                Ipv6AddrToken::DoubleColon,
            ] if a == "64" && b == "ff9b"
        )
        || is_isatap_suffix(itks);
    !is_transition_prefix
}

/// Returns `true` when the token list ends with one of the ISATAP
/// suffixes "[200:5efe:]", "[0:5efe:]" or "[::5efe:]".
fn is_isatap_suffix(itks: &[Ipv6AddrToken]) -> bool {
    let l = itks.len();
    (l >= 4
        && matches!(
            &itks[l - 4..],
            [
                Ipv6AddrToken::SixteenBit(a),
                Ipv6AddrToken::Colon,
                Ipv6AddrToken::SixteenBit(b),
                Ipv6AddrToken::Colon,
            ] if a == "200" && b == "5efe"
        ))
        || (l >= 4
            && matches!(
                &itks[l - 4..],
                [
                    Ipv6AddrToken::AllZeros,
                    Ipv6AddrToken::Colon,
                    Ipv6AddrToken::SixteenBit(b),
                    Ipv6AddrToken::Colon,
                ] if b == "5efe"
            ))
        || (l >= 3
            && matches!(
                &itks[l - 3..],
                [
                    Ipv6AddrToken::DoubleColon,
                    Ipv6AddrToken::SixteenBit(b),
                    Ipv6AddrToken::Colon,
                ] if b == "5efe"
            ))
}

/// Rewrites an embedded IPv4 address into the corresponding list of pure
/// IPv6 address tokens.
///
/// An IPv4 address `a.b.c.d` becomes the two 16-Bit chunks
/// `SixteenBit(hex(a) <> pad(hex(b)))` and
/// `SixteenBit(hex(c) <> pad(hex(d)))`, separated by a colon.
pub(crate) fn ipv4_addr_to_ipv6_addr_tokens(t: &Ipv6AddrToken) -> Ipv6AddrTokens {
    match t {
        Ipv6AddrToken::Ipv4Addr(a) => {
            let mut out = Ipv6AddrTokens::new();
            let mut groups = a.split('.');
            let n0 = hex_digits_of(groups.next());
            let n1 = hex_digits_of(groups.next());
            let n2 = hex_digits_of(groups.next());
            let n3 = hex_digits_of(groups.next());
            out.push(Ipv6AddrToken::SixteenBit(n0 + &add_zero(&n1)));
            out.push(Ipv6AddrToken::Colon);
            out.push(Ipv6AddrToken::SixteenBit(n2 + &add_zero(&n3)));
            out
        }
        other => {
            let mut out = Ipv6AddrTokens::new();
            out.push(other.clone());
            out
        }
    }
}

/// Returns the lowercase hexadecimal digits of a decimal IPv4 address group.
fn hex_digits_of(group: Option<&str>) -> String {
    match group.and_then(|g| g.parse::<u8>().ok()) {
        Some(n) => format!("{n:x}"),
        None => String::new(),
    }
}

/// Left-pads a single hexadecimal digit with a `0`.
fn add_zero(d: &str) -> String {
    if d.len() == 1 {
        format!("0{d}")
    } else {
        d.to_owned()
    }
}

/// Expands the tokens of an IPv6 address to their full
/// 4-hexadecimal-digit form.
pub(crate) fn expand_tokens(tks: &Ipv6AddrTokens) -> Ipv6AddrTokens {
    tks.iter()
        .map(|t| match t {
            Ipv6AddrToken::SixteenBit(s) => Ipv6AddrToken::SixteenBit(pad_left_4(s)),
            Ipv6AddrToken::AllZeros => Ipv6AddrToken::SixteenBit(String::from("0000")),
            other => other.clone(),
        })
        .collect()
}

/// Pads a hexadecimal chunk to 4 digits, leading `0`s included.
fn pad_left_4(s: &str) -> String {
    let mut out = String::with_capacity(4);
    for _ in s.len()..4 {
        out.push('0');
    }
    out.push_str(s);
    out
}

/// Replaces the unique double-colon token by the corresponding number of
/// all-zero chunks.
pub(crate) fn from_double_colon(tks: &Ipv6AddrTokens) -> Ipv6AddrTokens {
    let dc_index = match tks
        .iter()
        .position(|t| matches!(t, Ipv6AddrToken::DoubleColon))
    {
        Some(i) => i,
        None => return tks.clone(),
    };
    let fsts = &tks[..dc_index];
    let snds = &tks[dc_index + 1..];

    let mut out = Ipv6AddrTokens::new();
    // fste = if null fsts then [] else fsts <> [Colon]
    if !fsts.is_empty() {
        out.extend(fsts.iter().cloned());
        out.push(Ipv6AddrToken::Colon);
    }
    // allZerosTokensReplacement: intersperse Colon (replicate n AllZeros)
    let ntks = if count_ipv4_addr(tks) == 1 { 7 } else { 8 };
    let filled = tks
        .iter()
        .filter(|t| !matches!(t, Ipv6AddrToken::DoubleColon | Ipv6AddrToken::Colon))
        .count();
    let n = ntks - filled;
    out.extend(itertools::Itertools::intersperse(
        std::iter::repeat_n(Ipv6AddrToken::AllZeros, n),
        Ipv6AddrToken::Colon,
    ));
    // snde = if null snds then [] else Colon : snds
    if !snds.is_empty() {
        out.push(Ipv6AddrToken::Colon);
        out.extend(snds.iter().cloned());
    }
    out
}

/// Replaces the longest run of consecutive all-zero chunks by a unique
/// double-colon token.
///
/// No replacement happens when there is no all-zero chunk, and
/// "The symbol '::' MUST NOT be used to shorten just one 16-bit 0 field"
/// (RFC 5952, 4.2.2) when the longest run is a single chunk.
pub(crate) fn to_double_colon(tks: &Ipv6AddrTokens) -> Ipv6AddrTokens {
    // Runs of consecutive equal tokens, ignoring colons.
    let filtered: Vec<Ipv6AddrToken> = tks
        .iter()
        .filter(|t| !matches!(t, Ipv6AddrToken::Colon))
        .cloned()
        .collect();
    // Group by whether the token is an all-zero chunk or not: consecutive
    // non-zero runs merge, but the (AllZeros, length) runs are preserved.
    let runs: Vec<(bool, usize)> = filtered
        .iter()
        .chunk_by(|t| matches!(t, Ipv6AddrToken::AllZeros))
        .into_iter()
        .map(|(k, group)| (k, group.count()))
        .collect();
    // Longest all-zeros run length; the index of its first element in
    // `filtered` is the sum of the lengths of the preceding runs.
    let longest = runs
        .iter()
        .filter(|(k, _)| *k)
        .map(|(_, l)| *l)
        .max()
        .unwrap_or(0);
    let mut idx = 0usize;
    let mut found = false;
    for (k, l) in &runs {
        if *k && *l == longest {
            found = true;
            break;
        }
        idx += l;
    }
    if !found || longest <= 1 {
        return tks.clone();
    }
    let mut out = Ipv6AddrTokens::new();
    out.extend(itertools::Itertools::intersperse(
        filtered[..idx].iter().cloned(),
        Ipv6AddrToken::Colon,
    ));
    out.push(Ipv6AddrToken::DoubleColon);
    out.extend(itertools::Itertools::intersperse(
        filtered[idx + longest..].iter().cloned(),
        Ipv6AddrToken::Colon,
    ));
    out
}

/// Returns the text representation of the canonized IPv6 address from a
/// list of tokens.
pub(crate) fn ipv6_tokens_to_ipv6_addr(tks: &Ipv6AddrTokens) -> Option<Ipv6Addr> {
    Some(Ipv6Addr::from(ipv6_tokens_to_text(tks)))
}

/// Converts the hexadecimal text of a 16-Bit chunk to its integer value.
fn hex_text_to_int(s: &str) -> u16 {
    s.bytes().fold(0u16, |n, c| n * 16 + hex_digit_to_int(c))
}

/// Returns the value of a hexadecimal digit, `0` for anything else.
fn hex_digit_to_int(c: u8) -> u16 {
    match c {
        b'0'..=b'9' => u16::from(c - b'0'),
        b'a'..=b'f' => u16::from(c - b'a' + 10),
        b'A'..=b'F' => u16::from(c - b'A' + 10),
        _ => 0,
    }
}

/// Converts pure IPv6 tokens (after `from_double_colon`) to a
/// `std::net::Ipv6Addr`.
pub(crate) fn tokens_to_ipv6(tks: &Ipv6AddrTokens) -> Option<std::net::Ipv6Addr> {
    let expanded = from_double_colon(tks);
    let chunks: SmallVec<[u16; 8]> = expanded
        .iter()
        .filter_map(|t| match t {
            Ipv6AddrToken::SixteenBit(s) => Some(hex_text_to_int(s)),
            Ipv6AddrToken::AllZeros => Some(0),
            _ => None,
        })
        .collect();
    if chunks.len() != 8 {
        return None;
    }
    let segments: [u16; 8] = match chunks.as_slice().try_into() {
        Ok(s) => s,
        Err(_) => return None,
    };
    Some(std::net::Ipv6Addr::from(segments))
}

// NOTE: `networkInterfacesIPv6AddrList` (getting the IPv6 addresses of the
// local network interfaces) is not portable: it relies on OS-specific
// network interfaces information. It is left out of this port.

/// Parses a MAC address of the form `hh:hh:hh:hh:hh:hh` into the
/// tokenized IPv6 address of its 12 hexadecimal digits.
pub(crate) fn mac_addr(input: &str) -> Option<Ipv6AddrTokens> {
    let bytes = input.as_bytes();
    if bytes.len() != 17 {
        return None;
    }
    for (i, &b) in bytes.iter().enumerate() {
        if i % 3 == 2 {
            if b != b':' {
                return None;
            }
        } else if !is_hex_byte(b) {
            return None;
        }
    }
    let hex: String = bytes
        .iter()
        .filter(|&&b| b != b':')
        .map(|&b| b.to_ascii_lowercase() as char)
        .collect();
    ipv6_addr_tokens(&hex)
}

/// Parses a 16-Bit chunk token: 1 to 4 hexadecimal digits.
///
/// "Leading zeros MUST be suppressed" (RFC 5952, 4.1) and
/// hexadecimal digits MUST be in lowercase (RFC 5952, 4.3).
fn parse_sixteen_bit(input: &str) -> Option<(Ipv6AddrToken, &str)> {
    let bytes = input.as_bytes();
    let n = bytes
        .iter()
        .take(4)
        .take_while(|&&b| is_hex_byte(b))
        .count();
    if n == 0 {
        return None;
    }
    let lower = input[..n].to_ascii_lowercase();
    let trimmed = lower.trim_start_matches('0');
    let token = if trimmed.is_empty() {
        Ipv6AddrToken::AllZeros
    } else {
        Ipv6AddrToken::SixteenBit(trimmed.to_owned())
    };
    Some((token, &input[n..]))
}

/// Parses an embedded IPv4 address token: four decimal groups in
/// `0`..=`255`, dot-separated, canonized without leading zeros.
fn parse_ipv4_addr(input: &str) -> Option<(Ipv6AddrToken, &str)> {
    let bytes = input.as_bytes();
    let mut groups = [0u8; 4];
    let mut idx = 0;
    for (g, group) in groups.iter_mut().enumerate() {
        let start = idx;
        while idx < bytes.len() && is_digit_byte(bytes[idx]) {
            idx += 1;
        }
        if idx == start {
            return None;
        }
        let mut v = 0u32;
        for &b in &bytes[start..idx] {
            v = v * 10 + u32::from(b - b'0');
            if v > 255 {
                return None;
            }
        }
        *group = v as u8;
        if g < 3 {
            if idx >= bytes.len() || bytes[idx] != b'.' {
                return None;
            }
            idx += 1;
        }
    }
    let text = groups.iter().map(u8::to_string).join(".");
    Some((Ipv6AddrToken::Ipv4Addr(text), &input[idx..]))
}

/// Parses a `DoubleColon` token.
fn parse_double_colon(input: &str) -> Option<(Ipv6AddrToken, &str)> {
    input
        .strip_prefix("::")
        .map(|rest| (Ipv6AddrToken::DoubleColon, rest))
}

/// Parses a `Colon` token.
fn parse_colon(input: &str) -> Option<(Ipv6AddrToken, &str)> {
    input
        .strip_prefix(':')
        .map(|rest| (Ipv6AddrToken::Colon, rest))
}

/// Returns `true` when the byte is an hexadecimal digit.
fn is_hex_byte(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// Returns `true` when the byte is a decimal digit.
fn is_digit_byte(b: u8) -> bool {
    b.is_ascii_digit()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a token list from a raw textual form, or fails the test.
    fn tks_of(text: &str) -> Ipv6AddrTokens {
        ipv6_addr_tokens(text).expect("the text should tokenize")
    }

    /// Returns the canonized text of a token list, or fails the test.
    fn text_of(tks: &Ipv6AddrTokens) -> String {
        ipv6_tokens_to_text(tks)
    }

    #[test]
    fn ipv6_tokens_to_text_concatenates_token_texts() {
        let mut tks = Ipv6AddrTokens::new();
        tks.push(Ipv6AddrToken::SixteenBit(String::from("2001")));
        tks.push(Ipv6AddrToken::Colon);
        tks.push(Ipv6AddrToken::DoubleColon);
        tks.push(Ipv6AddrToken::SixteenBit(String::from("1")));
        assert_eq!(text_of(&tks), "2001:::1");
    }

    #[test]
    fn all_zeros_token_is_rendered_as_a_single_zero() {
        let mut tks = Ipv6AddrTokens::new();
        tks.push(Ipv6AddrToken::SixteenBit(String::from("1")));
        tks.push(Ipv6AddrToken::Colon);
        tks.push(Ipv6AddrToken::AllZeros);
        assert_eq!(text_of(&tks), "1:0");
    }

    #[test]
    fn ipv6_addr_is_valid() {
        assert!(is_ipv6_addr(&tks_of("1:2:3:4:5:6:7:8")));
        assert!(is_ipv6_addr(&tks_of("1::2")));
        assert!(is_ipv6_addr(&tks_of("::1")));
        assert!(is_ipv6_addr(&tks_of("::")));
        assert!(is_ipv6_addr(&tks_of("::1:2:3:4:5:6:7")));
        assert!(is_ipv6_addr(&tks_of("::ffff:192.0.2.128")));
        assert!(is_ipv6_addr(&tks_of("64:ff9b::1.2.3.4")));
    }

    #[test]
    fn ipv6_addr_is_invalid() {
        assert!(!is_ipv6_addr(&Ipv6AddrTokens::new()));
        assert!(!is_ipv6_addr(&tks_of("1")));
        assert!(!is_ipv6_addr(&tks_of("1:2:3:4:5:6:7")));
        assert!(!is_ipv6_addr(&tks_of("1::2::3")));
        assert!(!is_ipv6_addr(&tks_of(":::")));
        assert!(!is_ipv6_addr(&tks_of("1:2:3:4:5:6:7:8:9")));
        assert!(!is_ipv6_addr(&tks_of("::1:2:3:4:5:6:7:8")));
        assert!(!is_ipv6_addr(&tks_of("1.2.3.4")));
    }

    #[test]
    fn ipv6_addr_is_invalid_when_chunks_are_adjacent() {
        let mut tks = Ipv6AddrTokens::new();
        tks.push(Ipv6AddrToken::SixteenBit(String::from("1")));
        tks.push(Ipv6AddrToken::SixteenBit(String::from("2")));
        assert!(!is_ipv6_addr(&tks));
    }

    #[test]
    fn from_double_colon_expands_the_double_colon() {
        assert_eq!(
            text_of(&from_double_colon(&tks_of("::"))),
            "0:0:0:0:0:0:0:0"
        );
        assert_eq!(
            text_of(&from_double_colon(&tks_of("1::"))),
            "1:0:0:0:0:0:0:0"
        );
        assert_eq!(
            text_of(&from_double_colon(&tks_of("::ffff:192.0.2.128"))),
            "0:0:0:0:0:ffff:192.0.2.128"
        );
        // No double colon: unchanged.
        let tks = tks_of("1:2:3:4:5:6:7:8");
        assert_eq!(from_double_colon(&tks), tks);
    }

    #[test]
    fn to_double_colon_compresses_long_zero_runs() {
        assert_eq!(
            text_of(&to_double_colon(&from_double_colon(&tks_of("::")))),
            "::"
        );
        let tks = tks_of("1:0:0:1");
        assert_eq!(text_of(&to_double_colon(&tks_of("1:0:0:1"))), "1::1");
        // A single zero chunk must not be shortened by "::" (RFC 5952, 4.2.2).
        assert_eq!(text_of(&tks), "1:0:0:1");
        assert_eq!(text_of(&to_double_colon(&tks_of("1:0:1"))), "1:0:1");
    }

    #[test]
    fn double_colon_round_trip_is_identity() {
        for text in [
            "1:2:3:4:5:6:7:8",
            "::1",
            "1::2",
            "::ffff:192.0.2.128",
            "64:ff9b::1.2.3.4",
        ] {
            let original = tks_of(text);
            let round = to_double_colon(&from_double_colon(&original));
            assert_eq!(round, original, "round trip of {text}");
        }
    }

    #[test]
    fn tok_ipv6_addr_canonizes_and_keeps_transition_ipv4() {
        // "0:0::FFFF:192.0.2.128" == "::ffff:192.0.2.128"
        let tks = tok_ipv6_addr("0:0::FFFF:192.0.2.128").expect("should parse");
        assert_eq!(text_of(&tks), "::ffff:192.0.2.128");
        // Well-known transition prefixes keep their embedded IPv4 text.
        assert_eq!(
            text_of(&tok_ipv6_addr("::ffff:1.2.3.4").expect("should parse")),
            "::ffff:1.2.3.4"
        );
        assert_eq!(
            text_of(&tok_ipv6_addr("::1.2.3.4").expect("should parse")),
            "::1.2.3.4"
        );
        assert_eq!(
            text_of(&tok_ipv6_addr("64:ff9b::1.2.3.4").expect("should parse")),
            "64:ff9b::1.2.3.4"
        );
        assert_eq!(
            text_of(&tok_ipv6_addr("fe80::5efe:192.0.2.1").expect("should parse")),
            "fe80::5efe:192.0.2.1"
        );
        // Any other embedded IPv4 address is rewritten to hexadecimal.
        assert_eq!(
            text_of(&tok_ipv6_addr("1:2:3:4:5:6:192.0.2.1").expect("should parse")),
            "1:2:3:4:5:6:c000:201"
        );
    }

    #[test]
    fn tok_ipv6_addr_canonizes_zeroes_and_case() {
        assert_eq!(
            text_of(
                &tok_ipv6_addr("2001:0DB8:002A:1005:0230:48ff:fe73:989d").expect("should parse")
            ),
            "2001:db8:2a:1005:230:48ff:fe73:989d"
        );
        assert_eq!(
            text_of(&tok_ipv6_addr("0:0:0:0:0:0:0:0").expect("should parse")),
            "::"
        );
        assert_eq!(
            text_of(&tok_ipv6_addr("1:0:0:0:0:0:0:1").expect("should parse")),
            "1::1"
        );
    }

    #[test]
    fn tok_pure_ipv6_addr_always_rewrites_the_ipv4_address() {
        // "::ffff:192.0.2.128" == "::ffff:c000:280"
        let tks = tok_pure_ipv6_addr("::ffff:192.0.2.128").expect("should parse");
        assert_eq!(text_of(&tks), "::ffff:c000:280");
        let tks = tok_pure_ipv6_addr("0:0::FFFF:192.0.2.128").expect("should parse");
        assert_eq!(text_of(&tks), "::ffff:c000:280");
    }

    #[test]
    fn full_expansion_pads_all_chunks_to_four_digits() {
        // "0000:0000:0000:0000:0000:ffff:c000:0280"
        let tks = tok_pure_ipv6_addr("::ffff:192.0.2.128").expect("should parse");
        let tks = from_double_colon(&tks);
        let tks = expand_tokens(&tks);
        assert_eq!(text_of(&tks), "0000:0000:0000:0000:0000:ffff:c000:0280");
    }

    #[test]
    fn ipv4_addr_is_rewritten_to_two_sixteen_bit_chunks() {
        let out =
            ipv4_addr_to_ipv6_addr_tokens(&Ipv6AddrToken::Ipv4Addr(String::from("127.0.0.1")));
        assert_eq!(
            out.as_slice(),
            [
                Ipv6AddrToken::SixteenBit(String::from("7f00")),
                Ipv6AddrToken::Colon,
                Ipv6AddrToken::SixteenBit(String::from("001")),
            ]
        );
        let out =
            ipv4_addr_to_ipv6_addr_tokens(&Ipv6AddrToken::Ipv4Addr(String::from("192.0.2.128")));
        assert_eq!(
            out.as_slice(),
            [
                Ipv6AddrToken::SixteenBit(String::from("c000")),
                Ipv6AddrToken::Colon,
                Ipv6AddrToken::SixteenBit(String::from("280")),
            ]
        );
    }

    #[test]
    fn tokenizer_normalizes_ipv4_groups_and_chunks() {
        let tks = tks_of("::192.000.002.01");
        assert_eq!(
            tks.as_slice(),
            [
                Ipv6AddrToken::DoubleColon,
                Ipv6AddrToken::Ipv4Addr(String::from("192.0.2.1")),
            ]
        );
        // All-zero chunk becomes an AllZeros token; hex is lowercased.
        let tks = tks_of("0:0:0:0:0:0:0:0");
        let chunks: Ipv6AddrTokens = tks
            .iter()
            .filter(|t| !matches!(t, Ipv6AddrToken::Colon))
            .cloned()
            .collect();
        assert!(chunks.iter().all(|t| matches!(t, Ipv6AddrToken::AllZeros)));
        let tks = tks_of("FE80::1");
        assert!(matches!(&tks[0], Ipv6AddrToken::SixteenBit(s) if s == "fe80"));
    }

    #[test]
    fn tokenizer_requires_full_consumption() {
        assert!(ipv6_addr_tokens("").is_none());
        assert!(ipv6_addr_tokens("1.2.3").is_none());
        assert!(ipv6_addr_tokens("1:2:g").is_none());
        assert!(ipv6_addr_tokens("g").is_none());
        assert!(ipv6_addr_tokens(" 1::1").is_none());
        assert!(ipv6_addr_tokens("1::1 ").is_none());
    }

    #[test]
    fn hex_text_to_int_converts_hexadecimal_text() {
        assert_eq!(hex_text_to_int("ffff"), 0xffff);
        assert_eq!(hex_text_to_int("0"), 0);
        assert_eq!(hex_text_to_int("beef"), 0xbeef);
        assert_eq!(hex_text_to_int("CAFE"), 0xcafe);
    }

    #[test]
    fn tokens_to_ipv6_builds_the_net_ipv6_addr() {
        let tks = tok_pure_ipv6_addr("::ffff:192.0.2.128").expect("should parse");
        let addr = tokens_to_ipv6(&tks).expect("should convert");
        assert_eq!(
            addr,
            std::net::Ipv6Addr::from([0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0280])
        );
    }

    #[test]
    fn mac_addr_parses_the_six_hex_pairs() {
        let tks = mac_addr("fa:1d:58:cc:95:16").expect("should parse");
        assert_eq!(
            tks.as_slice(),
            [
                Ipv6AddrToken::SixteenBit(String::from("fa1d")),
                Ipv6AddrToken::SixteenBit(String::from("58cc")),
                Ipv6AddrToken::SixteenBit(String::from("9516")),
            ]
        );
        assert!(mac_addr("fa:1d:58:cc:95:1").is_none());
        assert!(mac_addr("fa:1d:58:cc:95:16:ff").is_none());
        assert!(mac_addr("fa:1d:58:cc:95:1g").is_none());
    }
}
