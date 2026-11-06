//! Internal functions for tokenizing, validating and rewriting IPv6 addresses.
//!
//! Token lists are stored inline in a [`crate::types::Ipv6AddrTokens`] and
//! functions return an [`Option`] whenever the original design relied on a
//! `Maybe`.
//!
//! The functions are consumed by the public API in `crate::functions` and by
//! the canonical `Ipv6Addr` equality in `crate::types`.

use crate::types::{Ipv6Addr, Ipv6AddrToken, Ipv6AddrTokens};

/// Returns the corresponding text of a list of IPv6 address tokens.
///
/// Given an arbitrary list of IPv6 address tokens, returns the
/// corresponding text.
pub(crate) fn ipv6_tokens_to_text(tks: &Ipv6AddrTokens) -> String {
    let mut out = String::with_capacity(tks.len() * 4);
    for token in tks {
        out.push_str(ipv6_token_to_text(token));
    }
    out
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

/// Returns `true` when the text is the content of a valid
/// [`Ipv6AddrToken::SixteenBit`]: 1 to 4 hexadecimal digits.
///
/// This is the single definition of the `SixteenBit` invariant. Every
/// function of the library that emits a `SixteenBit` token goes through it,
/// so that an emitted token always holds 1 to 4 hexadecimal digits.
pub(crate) fn is_sixteen_bit(text: &str) -> bool {
    (1..=4).contains(&text.len()) && text.bytes().all(is_hex_byte)
}

/// Builds the canonized chunk token of an hexadecimal text, or `None`.
///
/// The text has to be 1 to 4 hexadecimal digits: leading zeros are then
/// suppressed and the digits lowercased (RFC 5952 4.1 and 4.3), an all
/// zeros text yielding an [`Ipv6AddrToken::AllZeros`] token.
pub(crate) fn canonized_sixteen_bit(text: &str) -> Option<Ipv6AddrToken> {
    if !is_sixteen_bit(text) {
        return None;
    }
    let trimmed = text.trim_start_matches('0');
    if trimmed.is_empty() {
        return Some(Ipv6AddrToken::AllZeros);
    }
    let mut digits = String::with_capacity(trimmed.len());
    for &byte in trimmed.as_bytes() {
        digits.push(byte.to_ascii_lowercase() as char);
    }
    Some(Ipv6AddrToken::SixteenBit(digits))
}

/// Builds a [`Ipv6AddrToken::SixteenBit`] from a text already known to be 1
/// to 4 hexadecimal digits.
pub(crate) fn valid_sixteen_bit(text: impl Into<String>) -> Ipv6AddrToken {
    let text = text.into();
    debug_assert!(is_sixteen_bit(&text));
    Ipv6AddrToken::SixteenBit(text)
}

/// Returns `true` if a list of IPv6 address tokens constitutes a valid
/// IPv6 address.
pub(crate) fn is_ipv6_addr(tks: &Ipv6AddrTokens) -> bool {
    // [] -> False
    if tks.is_empty() {
        return false;
    }

    // Validate the chunks and the token adjacencies in a single pass.
    let mut double_colons = 0usize;
    let mut ipv4_addrs = 0usize;
    let mut previous: Option<&Ipv6AddrToken> = None;
    for token in tks {
        match token {
            Ipv6AddrToken::SixteenBit(text) => {
                // A SixteenBit token must hold 1 to 4 hexadecimal digits.
                if !is_sixteen_bit(text) {
                    return false;
                }
            }
            Ipv6AddrToken::DoubleColon => double_colons += 1,
            Ipv6AddrToken::Ipv4Addr(_) => ipv4_addrs += 1,
            Ipv6AddrToken::AllZeros | Ipv6AddrToken::Colon => {}
        }
        if let Some(previous) = previous {
            match (previous, token) {
                // A "::" cannot be followed by another separator.
                (Ipv6AddrToken::DoubleColon, Ipv6AddrToken::Colon) => return false,
                // Two chunks must be separated by a colon, even after a "::".
                (
                    Ipv6AddrToken::SixteenBit(_) | Ipv6AddrToken::AllZeros,
                    Ipv6AddrToken::SixteenBit(_) | Ipv6AddrToken::AllZeros,
                ) => return false,
                // Colon and IPv4Addr tokens are transparent.
                _ => {}
            }
        }
        previous = Some(token);
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

    let lentks = tks.len();
    let Some(lasttk) = tks.last() else {
        return false;
    };
    let lenconst = (lentks == 15 && double_colons == 0) || (lentks < 15 && double_colons == 1);

    // The first token has to be a SixteenBit, a DoubleColon or an AllZeros chunk.
    let first_valid = matches!(
        tks[0],
        Ipv6AddrToken::SixteenBit(_) | Ipv6AddrToken::DoubleColon | Ipv6AddrToken::AllZeros
    );
    if !first_valid {
        return false;
    }

    match ipv4_addrs {
        0 => {
            matches!(
                lasttk,
                Ipv6AddrToken::SixteenBit(_) | Ipv6AddrToken::DoubleColon | Ipv6AddrToken::AllZeros
            ) && lenconst
        }
        1 => {
            matches!(lasttk, Ipv6AddrToken::Ipv4Addr(_))
                && ((lentks == 13 && double_colons == 0) || (lentks < 12 && double_colons == 1))
        }
        _ => false,
    }
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
    // The transition-prefix detection is defined on the compressed token
    // list, so compress before testing it.
    let tks = to_double_colon(from_double_colon(tks));
    if !ipv4_addr_rewrite(&tks) {
        return Some(tks);
    }
    // Rewriting the IPv4 tail can merge its zero chunks with a preceding zero
    // run: expand the existing compression again and recompress the result.
    let tks = rewrite_ipv4_tail(tks)?;
    Some(to_double_colon(from_double_colon(tks)))
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
    let tks = rewrite_ipv4_tail(from_double_colon(tks))?;
    Some(to_double_colon(tks))
}

/// Replaces the last token by its IPv6 token representation, if any.
///
/// An embedded IPv4 address becomes two 16-Bit chunks; any other token is
/// kept unchanged.
fn rewrite_ipv4_tail(mut tks: Ipv6AddrTokens) -> Option<Ipv6AddrTokens> {
    let last = tks.pop()?;
    tks.extend(ipv4_addr_to_ipv6_addr_tokens(last));
    Some(tks)
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
/// `(a << 8) | b` and `(c << 8) | d`, separated by a colon and canonized
/// without leading zeroes.
pub(crate) fn ipv4_addr_to_ipv6_addr_tokens(t: Ipv6AddrToken) -> Ipv6AddrTokens {
    match t {
        Ipv6AddrToken::Ipv4Addr(text) => {
            let mut out = Ipv6AddrTokens::new();
            if let Some([a, b, c, d]) = ipv4_octets(&text) {
                out.push(hex_chunk_token(u16::from(a) << 8 | u16::from(b)));
                out.push(Ipv6AddrToken::Colon);
                out.push(hex_chunk_token(u16::from(c) << 8 | u16::from(d)));
            }
            out
        }
        other => {
            let mut out = Ipv6AddrTokens::new();
            out.push(other);
            out
        }
    }
}

/// Parses the four decimal octets of a canonized dotted IPv4 address.
fn ipv4_octets(text: &str) -> Option<[u8; 4]> {
    let mut parts = text.split('.');
    let mut octets = [0u8; 4];
    for octet in &mut octets {
        *octet = parts.next()?.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(octets)
}

/// Builds the canonical token of a 16-Bit chunk value.
fn hex_chunk_token(value: u16) -> Ipv6AddrToken {
    if value == 0 {
        Ipv6AddrToken::AllZeros
    } else {
        valid_sixteen_bit(format!("{value:x}"))
    }
}

/// Expands the tokens of an IPv6 address to their full
/// 4-hexadecimal-digit form.
pub(crate) fn expand_tokens(tks: Ipv6AddrTokens) -> Ipv6AddrTokens {
    tks.into_iter()
        .map(|token| match token {
            Ipv6AddrToken::SixteenBit(s) => {
                if s.len() == 4 {
                    Ipv6AddrToken::SixteenBit(s)
                } else {
                    valid_sixteen_bit(pad_left_4(&s))
                }
            }
            Ipv6AddrToken::AllZeros => valid_sixteen_bit("0000"),
            other => other,
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
pub(crate) fn from_double_colon(tks: Ipv6AddrTokens) -> Ipv6AddrTokens {
    let mut dc_index = None;
    let mut ipv4_addrs = 0usize;
    let mut filled = 0usize;
    for (index, token) in tks.iter().enumerate() {
        match token {
            Ipv6AddrToken::DoubleColon => {
                if dc_index.is_none() {
                    dc_index = Some(index);
                }
            }
            Ipv6AddrToken::Colon => {}
            Ipv6AddrToken::Ipv4Addr(_) => {
                ipv4_addrs += 1;
                filled += 1;
            }
            _ => filled += 1,
        }
    }
    let Some(dc_index) = dc_index else {
        return tks;
    };

    // An embedded IPv4 token stands for two 16-Bit chunks, hence one less
    // explicit token to fill.
    let ntks = if ipv4_addrs == 1 { 7 } else { 8 };
    // A valid token list never fills more than `ntks` chunks. Saturating keeps
    // a malformed list from underflowing into a huge zero-chunk run.
    debug_assert!(filled <= ntks);
    let n = ntks.saturating_sub(filled);

    let mut out = Ipv6AddrTokens::new();
    let mut tokens = tks.into_iter();
    let mut firsts = 0usize;
    for token in tokens.by_ref().take(dc_index) {
        out.push(token);
        firsts += 1;
    }
    let _double_colon = tokens.next();
    if firsts > 0 {
        out.push(Ipv6AddrToken::Colon);
    }
    for index in 0..n {
        if index > 0 {
            out.push(Ipv6AddrToken::Colon);
        }
        out.push(Ipv6AddrToken::AllZeros);
    }
    let mut has_seconds = false;
    for token in tokens {
        if !has_seconds {
            out.push(Ipv6AddrToken::Colon);
            has_seconds = true;
        }
        out.push(token);
    }
    out
}

/// Replaces the longest run of consecutive all-zero chunks by a unique
/// double-colon token.
///
/// No replacement happens when there is no all-zero chunk, and
/// "The symbol '::' MUST NOT be used to shorten just one 16-bit 0 field"
/// (RFC 5952, 4.2.2) when the longest run is a single chunk.
pub(crate) fn to_double_colon(tks: Ipv6AddrTokens) -> Ipv6AddrTokens {
    // Find the first longest run of zero chunks, ignoring colons.
    let mut best_start = 0usize;
    let mut best_len = 0usize;
    let mut run_start = 0usize;
    let mut run_len = 0usize;
    for (index, token) in tks
        .iter()
        .filter(|t| !matches!(t, Ipv6AddrToken::Colon))
        .enumerate()
    {
        if matches!(token, Ipv6AddrToken::AllZeros) {
            if run_len == 0 {
                run_start = index;
            }
            run_len += 1;
            if run_len > best_len {
                best_start = run_start;
                best_len = run_len;
            }
        } else {
            run_len = 0;
        }
    }
    if best_len <= 1 {
        return tks;
    }

    let mut out = Ipv6AddrTokens::new();
    let mut tokens = tks
        .into_iter()
        .filter(|token| !matches!(token, Ipv6AddrToken::Colon));
    let mut has_prefix = false;
    for token in tokens.by_ref().take(best_start) {
        if has_prefix {
            out.push(Ipv6AddrToken::Colon);
        }
        out.push(token);
        has_prefix = true;
    }
    for _ in 0..best_len {
        let _zero = tokens.next();
    }
    out.push(Ipv6AddrToken::DoubleColon);
    let mut has_suffix = false;
    for token in tokens {
        if has_suffix {
            out.push(Ipv6AddrToken::Colon);
        }
        out.push(token);
        has_suffix = true;
    }
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
pub(crate) fn tokens_to_ipv6(tks: Ipv6AddrTokens) -> Option<std::net::Ipv6Addr> {
    let expanded = from_double_colon(tks);
    let mut segments = [0u16; 8];
    let mut index = 0usize;
    for token in &expanded {
        match token {
            Ipv6AddrToken::SixteenBit(text) => {
                if index == segments.len() {
                    return None;
                }
                segments[index] = hex_text_to_int(text);
                index += 1;
            }
            Ipv6AddrToken::AllZeros => {
                if index == segments.len() {
                    return None;
                }
                index += 1;
            }
            _ => {}
        }
    }
    if index != segments.len() {
        return None;
    }
    Some(std::net::Ipv6Addr::from(segments))
}

/// Converts the text of an IPv6 address into a `std::net::Ipv6Addr`, or
/// returns `None` when the text is not a valid IPv6 address.
///
/// An embedded IPv4 address is always rewritten as hexadecimal digits
/// before the conversion.
pub(crate) fn ipv6_addr_to_std(addr: &Ipv6Addr) -> Option<std::net::Ipv6Addr> {
    let tks = tok_pure_ipv6_addr(&addr.0)?;
    tokens_to_ipv6(tks)
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
    let mut chunks = [0u16; 3];
    let mut chunk_index = 0usize;
    let mut nibbles = 0usize;
    let mut value = 0u16;
    for (index, &byte) in bytes.iter().enumerate() {
        if index % 3 == 2 {
            if byte != b':' {
                return None;
            }
            continue;
        }
        if !is_hex_byte(byte) {
            return None;
        }
        value = (value << 4) | hex_digit_to_int(byte);
        nibbles += 1;
        if nibbles == 4 {
            if chunk_index >= chunks.len() {
                return None;
            }
            chunks[chunk_index] = value;
            chunk_index += 1;
            nibbles = 0;
            value = 0;
        }
    }
    if chunk_index != chunks.len() {
        return None;
    }
    let mut out = Ipv6AddrTokens::new();
    out.push(hex_chunk_token(chunks[0]));
    out.push(hex_chunk_token(chunks[1]));
    out.push(hex_chunk_token(chunks[2]));
    Some(out)
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
    let token = canonized_sixteen_bit(&input[..n])?;
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
    let mut text = String::with_capacity(15);
    for (index, &group) in groups.iter().enumerate() {
        if index > 0 {
            text.push('.');
        }
        push_decimal(&mut text, group);
    }
    Some((Ipv6AddrToken::Ipv4Addr(text), &input[idx..]))
}

/// Appends the decimal representation of an octet to a string.
fn push_decimal(out: &mut String, value: u8) {
    if value >= 100 {
        out.push((b'0' + value / 100) as char);
        out.push((b'0' + (value / 10) % 10) as char);
        out.push((b'0' + value % 10) as char);
    } else if value >= 10 {
        out.push((b'0' + value / 10) as char);
        out.push((b'0' + value % 10) as char);
    } else {
        out.push((b'0' + value) as char);
    }
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
    fn ipv6_addr_is_invalid_when_chunks_are_adjacent_after_a_double_colon() {
        // The tokenizer splits a long hexadecimal run into adjacent chunks.
        assert!(!is_ipv6_addr(&tks_of("::12ab34cd")));
        assert!(!is_ipv6_addr(&tks_of(
            "::123412341234123412341234123412341234"
        )));
    }

    #[test]
    fn from_double_colon_expands_the_double_colon() {
        assert_eq!(text_of(&from_double_colon(tks_of("::"))), "0:0:0:0:0:0:0:0");
        assert_eq!(
            text_of(&from_double_colon(tks_of("1::"))),
            "1:0:0:0:0:0:0:0"
        );
        assert_eq!(
            text_of(&from_double_colon(tks_of("::ffff:192.0.2.128"))),
            "0:0:0:0:0:ffff:192.0.2.128"
        );
        // No double colon: unchanged.
        let tks = tks_of("1:2:3:4:5:6:7:8");
        assert_eq!(from_double_colon(tks.clone()), tks);
    }

    #[test]
    fn to_double_colon_compresses_long_zero_runs() {
        assert_eq!(
            text_of(&to_double_colon(from_double_colon(tks_of("::")))),
            "::"
        );
        let tks = tks_of("1:0:0:1");
        assert_eq!(text_of(&to_double_colon(tks_of("1:0:0:1"))), "1::1");
        // A single zero chunk must not be shortened by "::" (RFC 5952, 4.2.2).
        assert_eq!(text_of(&tks), "1:0:0:1");
        assert_eq!(text_of(&to_double_colon(tks_of("1:0:1"))), "1:0:1");
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
            let round = to_double_colon(from_double_colon(original.clone()));
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
        let tks = from_double_colon(tks);
        let tks = expand_tokens(tks);
        assert_eq!(text_of(&tks), "0000:0000:0000:0000:0000:ffff:c000:0280");
    }

    #[test]
    fn ipv4_addr_is_rewritten_to_two_canonical_sixteen_bit_chunks() {
        let out = ipv4_addr_to_ipv6_addr_tokens(Ipv6AddrToken::Ipv4Addr(String::from("127.0.0.1")));
        assert_eq!(
            out.as_slice(),
            [
                Ipv6AddrToken::SixteenBit(String::from("7f00")),
                Ipv6AddrToken::Colon,
                Ipv6AddrToken::SixteenBit(String::from("1")),
            ]
        );
        let out =
            ipv4_addr_to_ipv6_addr_tokens(Ipv6AddrToken::Ipv4Addr(String::from("192.0.2.128")));
        assert_eq!(
            out.as_slice(),
            [
                Ipv6AddrToken::SixteenBit(String::from("c000")),
                Ipv6AddrToken::Colon,
                Ipv6AddrToken::SixteenBit(String::from("280")),
            ]
        );
        // Zero high bytes must not leave leading zeroes behind.
        let out = ipv4_addr_to_ipv6_addr_tokens(Ipv6AddrToken::Ipv4Addr(String::from("0.0.0.0")));
        assert_eq!(
            out.as_slice(),
            [
                Ipv6AddrToken::AllZeros,
                Ipv6AddrToken::Colon,
                Ipv6AddrToken::AllZeros
            ]
        );
        let out =
            ipv4_addr_to_ipv6_addr_tokens(Ipv6AddrToken::Ipv4Addr(String::from("61.62.63.64")));
        assert_eq!(
            out.as_slice(),
            [
                Ipv6AddrToken::SixteenBit(String::from("3d3e")),
                Ipv6AddrToken::Colon,
                Ipv6AddrToken::SixteenBit(String::from("3f40")),
            ]
        );
    }

    #[test]
    fn tok_ipv6_addr_recompresses_after_rewriting_the_ipv4_tail() {
        assert_eq!(
            text_of(&tok_ipv6_addr("1:2:3:4:5:6:0.0.0.0").expect("should parse")),
            "1:2:3:4:5:6::"
        );
        assert_eq!(
            text_of(&tok_ipv6_addr("1::0.0.0.1").expect("should parse")),
            "1::1"
        );
        assert_eq!(
            text_of(&tok_pure_ipv6_addr("1::0.0.0.1").expect("should parse")),
            "1::1"
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
    fn is_sixteen_bit_accepts_one_to_four_hexadecimal_digits() {
        for text in ["0", "1", "a", "F", "00", "0a", "ffff", "ABCD", "0000"] {
            assert!(
                is_sixteen_bit(text),
                "{text:?} is 1 to 4 hexadecimal digits"
            );
        }
        for text in ["", "00000", "g", "12g4", " 1", "1 ", "-1", "ab\n"] {
            assert!(
                !is_sixteen_bit(text),
                "{text:?} is not 1 to 4 hexadecimal digits"
            );
        }
    }

    #[test]
    fn canonized_sixteen_bit_drops_leading_zeroes_and_lowercases() {
        assert_eq!(canonized_sixteen_bit("0000"), Some(Ipv6AddrToken::AllZeros));
        assert_eq!(
            canonized_sixteen_bit("0f00"),
            Some(Ipv6AddrToken::SixteenBit(String::from("f00")))
        );
        assert_eq!(
            canonized_sixteen_bit("ABCD"),
            Some(Ipv6AddrToken::SixteenBit(String::from("abcd")))
        );
        assert_eq!(
            canonized_sixteen_bit("ffff"),
            Some(Ipv6AddrToken::SixteenBit(String::from("ffff")))
        );
        assert_eq!(canonized_sixteen_bit(""), None);
        assert_eq!(canonized_sixteen_bit("00000"), None);
        assert_eq!(canonized_sixteen_bit("zzzz"), None);
    }

    #[test]
    fn valid_sixteen_bit_builds_an_hexadecimal_chunk() {
        assert_eq!(
            valid_sixteen_bit("beef"),
            Ipv6AddrToken::SixteenBit(String::from("beef"))
        );
    }

    #[test]
    fn is_ipv6_addr_rejects_a_malformed_sixteen_bit_content() {
        let mut tks = Ipv6AddrTokens::new();
        tks.push(Ipv6AddrToken::SixteenBit(String::from("1")));
        tks.push(Ipv6AddrToken::Colon);
        tks.push(Ipv6AddrToken::SixteenBit(String::from("zzzz")));
        tks.push(Ipv6AddrToken::Colon);
        tks.push(Ipv6AddrToken::SixteenBit(String::from("2")));
        tks.push(Ipv6AddrToken::Colon);
        tks.push(Ipv6AddrToken::SixteenBit(String::from("3")));
        tks.push(Ipv6AddrToken::Colon);
        tks.push(Ipv6AddrToken::SixteenBit(String::from("4")));
        tks.push(Ipv6AddrToken::Colon);
        tks.push(Ipv6AddrToken::SixteenBit(String::from("5")));
        tks.push(Ipv6AddrToken::Colon);
        tks.push(Ipv6AddrToken::SixteenBit(String::from("6")));
        assert!(!is_ipv6_addr(&tks));
    }

    #[test]
    fn tokens_to_ipv6_builds_the_net_ipv6_addr() {
        let tks = tok_pure_ipv6_addr("::ffff:192.0.2.128").expect("should parse");
        let addr = tokens_to_ipv6(tks).expect("should convert");
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
