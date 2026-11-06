//! Fast paths for the IPv6 address text conversions.
//!
//! The token based implementation in [`crate::internals`] is the reference:
//! it accepts a few forms that `std::net::Ipv6Addr` rejects, such as dotted
//! IPv4 groups with leading zeroes. The functions here use the standard
//! library parser whenever it succeeds and render the text from the address
//! segments, which avoids the token allocations. The callers fall back to the
//! token implementation when [`parse`] returns `None`.

use std::fmt::Write;
use std::net::Ipv6Addr;

/// Capacity of a canonical address: eight four-digit chunks and seven colons.
const CANONICAL_CAPACITY: usize = 39;
/// Capacity of a canonical address with a dotted IPv4 tail, which is at most
/// six four-digit chunks, six colons and "255.255.255.255".
const CANONICAL_IPV4_CAPACITY: usize = 45;
/// Capacity of a reverse lookup domain name.
const ARPA_CAPACITY: usize = 73;
/// Capacity of a Windows UNC path name.
const UNC_CAPACITY: usize = 56;

const ARPA_SUFFIX: &str = "IP6.ARPA.";
const UNC_SUFFIX: &str = ".ipv6-literal.net";
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Parses the text with the standard library parser.
pub(crate) fn parse(text: &str) -> Option<Ipv6Addr> {
    text.parse().ok()
}

/// Returns `true` when the text contains a dotted IPv4 address.
pub(crate) fn has_dotted_ipv4(text: &str) -> bool {
    text.as_bytes().contains(&b'.')
}

/// Returns `true` when the last 32-Bit of the address keep their dotted IPv4
/// text representation (RFC 5952 Section 5).
pub(crate) fn keeps_ipv4_tail(segments: [u16; 8]) -> bool {
    let all_zero = |chunks: &[u16]| chunks.iter().all(|&chunk| chunk == 0);
    // IPv4-compatible: "::a.b.c.d"
    all_zero(&segments[..6])
        // IPv4-mapped: "::ffff:a.b.c.d"
        || (all_zero(&segments[..5]) && segments[5] == 0xffff)
        // IPv4-translated: "::ffff:0:a.b.c.d"
        || (all_zero(&segments[..4]) && segments[4] == 0xffff && segments[5] == 0)
        // IPv4-translatable: "64:ff9b::a.b.c.d"
        || (segments[0] == 0x64 && segments[1] == 0xff9b && all_zero(&segments[2..6]))
        // ISATAP: "...:5efe:a.b.c.d", with 200:5efe, 0:5efe or ::5efe
        || (segments[5] == 0x5efe && matches!(segments[4], 0 | 0x0200))
}

/// Returns the canonical text representation of the address.
pub(crate) fn canonical(addr: Ipv6Addr, keep_ipv4_tail: bool) -> String {
    let capacity = if keep_ipv4_tail {
        CANONICAL_IPV4_CAPACITY
    } else {
        CANONICAL_CAPACITY
    };
    render(addr.segments(), keep_ipv4_tail, ':', capacity)
}

/// Returns the canonical text representation, always in hexadecimal digits.
pub(crate) fn pure(addr: Ipv6Addr) -> String {
    canonical(addr, false)
}

/// Returns the fully expanded text representation of the address.
pub(crate) fn full(addr: Ipv6Addr) -> String {
    let segments = addr.segments();
    let mut out = String::with_capacity(CANONICAL_CAPACITY);
    for (index, segment) in segments.iter().enumerate() {
        if index > 0 {
            out.push(':');
        }
        push_hex_chunk_padded(&mut out, *segment);
    }
    out
}

/// Returns the reverse lookup domain name of the address (RFC 3596).
pub(crate) fn arpa(addr: Ipv6Addr) -> String {
    let mut out = String::with_capacity(ARPA_CAPACITY);
    for byte in addr.octets().iter().rev() {
        out.push(HEX[usize::from(byte & 0x0f)] as char);
        out.push('.');
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push('.');
    }
    out.push_str(ARPA_SUFFIX);
    out
}

/// Returns the Windows UNC path name of the address.
pub(crate) fn unc(addr: Ipv6Addr) -> String {
    // Reserve the whole result so that appending the suffix never reallocates.
    let mut out = render(addr.segments(), false, '-', UNC_CAPACITY);
    out.push_str(UNC_SUFFIX);
    out
}

/// Returns the text representation used by `std::net::Ipv6Addr`.
pub(crate) fn std_display(addr: Ipv6Addr) -> String {
    let segments = addr.segments();
    let is_mapped = segments[..5].iter().all(|&segment| segment == 0) && segments[5] == 0xffff;
    canonical(addr, is_mapped)
}

/// Renders the segments with the longest zero run compressed to a double
/// separator.
///
/// When `keep_ipv4_tail` is `true`, the last two segments are rendered as a
/// dotted IPv4 address and are left out of the zero run search, so that an
/// all-zero IPv4 tail keeps its text representation.
fn render(segments: [u16; 8], keep_ipv4_tail: bool, separator: char, capacity: usize) -> String {
    let searchable = if keep_ipv4_tail { 6 } else { 8 };
    let (mut best_start, mut best_len) = (0usize, 0usize);
    let (mut run_start, mut run_len) = (0usize, 0usize);
    for (index, &segment) in segments[..searchable].iter().enumerate() {
        if segment == 0 {
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

    let mut out = String::with_capacity(capacity);
    let mut index = 0usize;
    while index < 8 {
        if best_len > 1 && index == best_start {
            out.push(separator);
            out.push(separator);
            index += best_len;
            continue;
        }
        if keep_ipv4_tail && index == 6 {
            if !out.is_empty() && !out.ends_with(separator) {
                out.push(separator);
            }
            let _ = write!(
                out,
                "{}.{}.{}.{}",
                segments[6] >> 8,
                segments[6] & 0xff,
                segments[7] >> 8,
                segments[7] & 0xff
            );
            index = 8;
            continue;
        }
        if !out.is_empty() && !out.ends_with(separator) {
            out.push(separator);
        }
        push_hex_chunk(&mut out, segments[index]);
        index += 1;
    }
    out
}

/// Pushes a 16-Bit chunk as 1 to 4 lowercase hexadecimal digits.
fn push_hex_chunk(out: &mut String, chunk: u16) {
    let digits = if chunk == 0 {
        1
    } else {
        (16 - chunk.leading_zeros() as usize).div_ceil(4)
    };
    for index in (0..digits).rev() {
        out.push(HEX[usize::from((chunk >> (index * 4)) & 0x0f)] as char);
    }
}

/// Pushes a 16-Bit chunk as exactly 4 lowercase hexadecimal digits.
fn push_hex_chunk_padded(out: &mut String, chunk: u16) {
    for shift in [12, 8, 4, 0] {
        out.push(HEX[usize::from((chunk >> shift) & 0x0f)] as char);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internals::{
        expand_tokens, from_double_colon, ipv6_tokens_to_text, tok_ipv6_addr, tok_pure_ipv6_addr,
    };

    const CORPUS: &[&str] = &[
        "::",
        "::1",
        "1::",
        "2001:db8::1",
        "2001:db8:0:0:1:0:0:1",
        "FE80:CD00:0000:0CDE:1257:0000:211E:729C",
        "0000:0000:0000:0000:0000:0000:0000:0001",
        "::1.2.3.4",
        "::ffff:1.2.3.4",
        "::ffff:0:1.2.3.4",
        "64:ff9b::1.2.3.4",
        "fe80::5efe:1.2.3.4",
        "fe80::200:5efe:1.2.3.4",
        "0:0:0:0:0:ffff:192.0.2.1",
        "1:2:3:4:5:6:192.0.2.1",
        "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1",
    ];

    fn token_canonical(text: &str) -> Option<String> {
        tok_ipv6_addr(text).map(|tks| ipv6_tokens_to_text(&tks))
    }

    fn token_pure(text: &str) -> Option<String> {
        tok_pure_ipv6_addr(text).map(|tks| ipv6_tokens_to_text(&tks))
    }

    fn token_full(text: &str) -> Option<String> {
        tok_pure_ipv6_addr(text).map(|tks| {
            let tks = from_double_colon(tks);
            let tks = expand_tokens(tks);
            ipv6_tokens_to_text(&tks)
        })
    }

    fn fast_canonical(text: &str) -> Option<String> {
        parse(text).map(|addr| {
            let keep_ipv4 = has_dotted_ipv4(text) && keeps_ipv4_tail(addr.segments());
            canonical(addr, keep_ipv4)
        })
    }

    fn token_unc(text: &str) -> Option<String> {
        tok_pure_ipv6_addr(text).map(|tks| {
            let text = ipv6_tokens_to_text(&tks);
            let mut unc = String::with_capacity(text.len() + ".ipv6-literal.net".len());
            for c in text.chars() {
                unc.push(if c == ':' { '-' } else { c });
            }
            unc.push_str(".ipv6-literal.net");
            unc
        })
    }

    #[test]
    fn fast_path_matches_the_token_path() {
        for text in CORPUS {
            assert_eq!(
                fast_canonical(text),
                token_canonical(text),
                "canonical form of {text}"
            );
            assert_eq!(
                parse(text).map(pure),
                token_pure(text),
                "pure form of {text}"
            );
            assert_eq!(
                parse(text).map(full),
                token_full(text),
                "full form of {text}"
            );
        }
    }

    #[test]
    fn std_display_matches_the_standard_library() {
        for text in CORPUS {
            if let Some(addr) = parse(text) {
                assert_eq!(std_display(addr), addr.to_string(), "display of {text}");
            }
        }
    }

    #[test]
    fn arpa_and_unc_have_the_expected_lengths() {
        for text in CORPUS {
            if let Some(addr) = parse(text) {
                let arpa = arpa(addr);
                let unc = unc(addr);
                assert_eq!(arpa.len(), 73, "arpa length of {text}");
                assert!(arpa.ends_with(".IP6.ARPA."));
                assert!(unc.ends_with(".ipv6-literal.net"));
            }
        }
    }

    /// A small deterministic pseudo-random generator, so that the differential
    /// tests need no dependency.
    fn prng(seed: u64) -> impl FnMut() -> u64 {
        let mut state = seed;
        move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
    }

    /// Returns several valid text forms of the same address: compressed,
    /// fully expanded, zero-trimmed, uppercase and dotted IPv4 tail.
    fn text_forms(segments: [u16; 8]) -> Vec<String> {
        let addr = Ipv6Addr::from(segments);
        let mut forms = vec![addr.to_string(), addr.to_string().to_uppercase()];

        let padded = segments
            .iter()
            .map(|segment| format!("{segment:04x}"))
            .collect::<Vec<_>>()
            .join(":");
        let trimmed = segments
            .iter()
            .map(|segment| format!("{segment:x}"))
            .collect::<Vec<_>>()
            .join(":");
        forms.push(padded.clone());
        forms.push(padded.to_uppercase());
        forms.push(trimmed.clone());
        forms.push(trimmed.to_uppercase());

        let head = segments[..6]
            .iter()
            .map(|segment| format!("{segment:x}"))
            .collect::<Vec<_>>()
            .join(":");
        let dotted = format!(
            "{head}:{}.{}.{}.{}",
            segments[6] >> 8,
            segments[6] & 0xff,
            segments[7] >> 8,
            segments[7] & 0xff
        );
        forms.push(dotted.clone());
        forms.push(dotted.to_uppercase());

        forms
    }

    #[test]
    fn random_valid_addresses_match_the_token_path() {
        let mut next = prng(0x0123_4567_89ab_cdef);
        for _ in 0..512 {
            let mut segments = [0u16; 8];
            // Bias towards zero chunks so that compression is exercised.
            for segment in &mut segments {
                *segment = match next() % 4 {
                    0 => 0,
                    1 => 1,
                    2 => 0xffff,
                    _ => (next() & 0xffff) as u16,
                };
            }
            for text in text_forms(segments) {
                let addr = parse(&text)
                    .unwrap_or_else(|| panic!("generated form should be valid: {text:?}"));
                assert_eq!(
                    crate::ipv6_addr(&text).map(|addr| addr.0),
                    token_canonical(&text),
                    "canonical form of {text:?}"
                );
                assert_eq!(
                    crate::pure_ipv6_addr(&text).map(|addr| addr.0),
                    token_pure(&text),
                    "pure form of {text:?}"
                );
                assert_eq!(
                    crate::full_ipv6_addr(&text).map(|addr| addr.0),
                    token_full(&text),
                    "full form of {text:?}"
                );
                assert_eq!(
                    std_display(addr),
                    Ipv6Addr::from(segments).to_string(),
                    "std display of {text:?}"
                );
                assert_eq!(
                    crate::to_unc(&crate::Ipv6Addr::from(text.as_str())).as_deref(),
                    token_unc(&text).as_deref(),
                    "UNC form of {text:?}"
                );
            }
        }
    }

    #[test]
    fn std_accepted_inputs_are_also_accepted_by_the_token_path() {
        // Deterministic pseudo-random strings from the IPv6 text alphabet.
        let alphabet = b"0123456789abcdefABCDEF:.";
        let mut next = prng(0x9e37_79b9_7f4a_7c15);
        for _ in 0..10_000 {
            let len = (next() % 46) as usize;
            let text: String = (0..len)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize] as char)
                .collect();
            if let Some(addr) = parse(&text) {
                let tks = tok_pure_ipv6_addr(&text)
                    .unwrap_or_else(|| panic!("the token path should accept {text:?}"));
                let token_addr = crate::internals::tokens_to_ipv6(tks)
                    .unwrap_or_else(|| panic!("the token path should convert {text:?}"));
                assert_eq!(token_addr, addr, "address value of {text:?}");
            }
        }
    }
}
