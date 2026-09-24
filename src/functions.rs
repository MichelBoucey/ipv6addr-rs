//! Public functions: parsing, conversion and random generation of IPv6
//! addresses.
//!
//! All the functions build on the tokenization and rewriting internals and
//! expose the API of the original `Text.IPv6Addr` module, with an [`Option`]
//! standing in for the `Maybe` monad.

use crate::internals::{
    expand_tokens, from_double_colon, ipv6_addr_tokens, ipv6_tokens_to_ipv6_addr,
    ipv6_tokens_to_text, is_ipv6_addr, mac_addr, to_double_colon, tok_ipv6_addr,
    tok_pure_ipv6_addr, tokens_to_ipv6,
};
use crate::types::{Ipv6Addr, Ipv6AddrToken, Ipv6AddrTokens};

/// Returns `Some` of the text representation of a canonized IPv6 address in
/// conformation with RFC 5952, or `None`.
///
/// An embedded IPv4 address keeps its IPv4 text representation when it
/// stands for a well-known IPv4/IPv6 transition prefix (RFC 5952
/// Section 5): IPv4-compatible "::1.2.3.4", IPv4-mapped "::ffff:1.2.3.4",
/// IPv4-translated "::ffff:0:1.2.3.4", IPv4-translatable "64:ff9b::1.2.3.4"
/// or ISATAP "fe80::5efe:1.2.3.4" addresses.
///
/// > ipv6_addr("0:0::FFFF:192.0.2.128") == Some(Ipv6Addr("::ffff:192.0.2.128"))
pub fn ipv6_addr(text: &str) -> Option<Ipv6Addr> {
    tok_ipv6_addr(text).and_then(|tks| ipv6_tokens_to_ipv6_addr(&tks))
}

/// Returns `Some` of a pure IPv6 address, or `None`.
///
/// An embedded IPv4 address is always rewritten as hexadecimal digits:
///
/// > pure_ipv6_addr("::ffff:192.0.2.128") == Some(Ipv6Addr("::ffff:c000:280"))
pub fn pure_ipv6_addr(text: &str) -> Option<Ipv6Addr> {
    tok_pure_ipv6_addr(text).and_then(|tks| ipv6_tokens_to_ipv6_addr(&tks))
}

/// Returns `Some` of a pure and fully expanded IPv6 address, or `None`.
///
/// The "::" compression is expanded to its unspoken zero chunks, each
/// 16-Bit chunk being padded to four hexadecimal digits:
///
/// > full_ipv6_addr("::ffff:192.0.2.128") ==
/// >   Some(Ipv6Addr("0000:0000:0000:0000:0000:ffff:c000:0280"))
pub fn full_ipv6_addr(text: &str) -> Option<Ipv6Addr> {
    let tks = tok_pure_ipv6_addr(text)?;
    let tks = from_double_colon(&tks);
    let tks = expand_tokens(&tks);
    ipv6_tokens_to_ipv6_addr(&tks)
}

/// Returns the reverse lookup domain name corresponding to the given IPv6
/// address (RFC 3596 Section 2.5).
///
/// The sixteen address bytes are expanded to their hexadecimal digits
/// which are then reversed, each nibble being separated by a dot.
///
/// > to_ip6_arpa(&Ipv6Addr::from("4321:0:1:2:3:4:567:89ab")) ==
/// >   Some("b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.IP6.ARPA.")
pub fn to_ip6_arpa(addr: &Ipv6Addr) -> Option<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let tks = tok_pure_ipv6_addr(&addr.0)?;
    let net = tokens_to_ipv6(&tks)?;
    let mut hex = String::with_capacity(32);
    for byte in net.octets() {
        hex.push(HEX[usize::from(byte >> 4)] as char);
        hex.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    let mut arpa = String::with_capacity(63 + ".IP6.ARPA.".len());
    arpa.extend(itertools::Itertools::intersperse(hex.chars().rev(), '.'));
    arpa.push_str(".IP6.ARPA.");
    Some(arpa)
}

/// Returns the Windows UNC path name of the given IPv6 address.
///
/// The ":" chunk separators are replaced by "-" and the hextets are
/// canonized (colon compression and lower case):
///
/// > to_unc(&Ipv6Addr::from("2001:0DB8:002a:1005:230:48ff:fe73:989d")) ==
/// >   Some("2001-db8-2a-1005-230-48ff-fe73-989d.ipv6-literal.net")
pub fn to_unc(addr: &Ipv6Addr) -> Option<String> {
    let tks = tok_pure_ipv6_addr(&addr.0)?;
    let text = ipv6_tokens_to_text(&tks);
    let mut unc = String::with_capacity(text.len() + ".ipv6-literal.net".len());
    for c in text.chars() {
        if c == ':' {
            unc.push('-');
        } else {
            unc.push(c);
        }
    }
    unc.push_str(".ipv6-literal.net");
    Some(unc)
}

/// A small, non-cryptographic pseudo-random number generator (xorshift64*).
///
/// Like System.Random it is not cryptographically secure. The public random
/// functions seed it from the system clock; the explicitly seeded variant is
/// used by the tests to stay deterministic.
struct XorShift64Star(u64);

impl XorShift64Star {
    /// Seeds the generator from the system clock.
    fn from_system_seed() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        // Mix the clock with a process-wide counter so that two generators
        // created within the same nanosecond do not share a sequence.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let counter =
            COUNTER.fetch_add(0x9e37_79b9_7f4a_7c15, std::sync::atomic::Ordering::Relaxed);
        XorShift64Star::with_seed(nanos ^ counter.rotate_left(17))
    }

    /// Creates a generator with an explicit seed.
    ///
    /// A zero state would make every draw return zero, so it is avoided.
    fn with_seed(seed: u64) -> Self {
        XorShift64Star(if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Returns a random number in the inclusive `low..=high` range.
    fn next_range(&mut self, low: u64, high: u64) -> u64 {
        low + self.next_u64() % (high - low + 1)
    }

    /// Returns a random hexadecimal digit (0 to 15).
    fn next_hex_digit(&mut self) -> u8 {
        (self.next_u64() >> 60) as u8
    }
}

/// The hexadecimal digit corresponding to a value in 0..16.
fn hex_digit_char(digit: u8) -> char {
    if digit < 10 {
        (b'0' + digit) as char
    } else {
        (b'a' + digit - 10) as char
    }
}

/// Returns a random lowercase hexadecimal text of the given length.
fn random_hex(rng: &mut XorShift64Star, length: usize) -> String {
    let mut s = String::with_capacity(length);
    for _ in 0..length {
        s.push(hex_digit_char(rng.next_hex_digit()));
    }
    s
}

/// Returns a token list of a random partial IPv6 address of `n` 16-Bit
/// chunks, or an empty list when `n` is not in the 1..8 range.
///
/// > rand_partial_ipv6_addr(3) reads 3 random chunks separated by colons.
pub fn rand_partial_ipv6_addr(n: usize) -> Ipv6AddrTokens {
    rand_partial_ipv6_addr_with(&mut XorShift64Star::from_system_seed(), n)
}

/// The seeded core of [`rand_partial_ipv6_addr`].
fn rand_partial_ipv6_addr_with(rng: &mut XorShift64Star, n: usize) -> Ipv6AddrTokens {
    if n == 0 || n > 8 {
        return Ipv6AddrTokens::new();
    }
    let chunks = (0..n).map(|_| Ipv6AddrToken::SixteenBit(random_hex(rng, 4)));
    itertools::Itertools::intersperse(chunks, Ipv6AddrToken::Colon).collect()
}

/// Returns a random 16-Bit chunk built from a mask: each '_' is replaced by
/// a random hexadecimal digit, the other characters are kept as-is, then
/// the leading zeroes are dropped.
///
/// > rand_ipv6_addr_chunk("_f__") is a `SixteenBit` made of a random digit,
/// >   an "f" and two random digits.
pub fn rand_ipv6_addr_chunk(mask: &str) -> Ipv6AddrToken {
    rand_ipv6_addr_chunk_with(&mut XorShift64Star::from_system_seed(), mask)
}

/// The seeded core of [`rand_ipv6_addr_chunk`].
fn rand_ipv6_addr_chunk_with(rng: &mut XorShift64Star, mask: &str) -> Ipv6AddrToken {
    let built: String = mask
        .chars()
        .map(|c| {
            if c == '_' {
                hex_digit_char(rng.next_hex_digit())
            } else {
                c
            }
        })
        .collect();
    Ipv6AddrToken::SixteenBit(built.trim_start_matches('0').to_owned())
}

/// Returns a random IPv6 address, an embedded IPv4 address being always
/// rewritten as hexadecimal digits.
pub fn rand_ipv6_addr() -> Ipv6Addr {
    match rand_ipv6_addr_with_prefix_core(&mut XorShift64Star::from_system_seed(), None) {
        Some(addr) => addr,
        // The no-prefix path always draws a shape that is a valid address.
        None => unreachable!("a random address without prefix is always valid"),
    }
}

/// Returns a random IPv6 address completed with random 16-Bit chunks when a
/// prefix is given, or `None` when the prefix cannot be completed into a
/// valid address.
pub fn rand_ipv6_addr_with_prefix(prefix: Option<&str>) -> Option<Ipv6Addr> {
    rand_ipv6_addr_with_prefix_core(&mut XorShift64Star::from_system_seed(), prefix)
}

/// The seeded core of [`rand_ipv6_addr`] and [`rand_ipv6_addr_with_prefix`].
fn rand_ipv6_addr_with_prefix_core(
    rng: &mut XorShift64Star,
    prefix: Option<&str>,
) -> Option<Ipv6Addr> {
    let tks = match prefix {
        // Without a prefix, a random address shape is rolled first:
        // a "::" compression, or a single explicit zero chunk.
        None => {
            // r <- randomRIO (1, 8)
            let r = rng.next_range(1, 8);
            if r == 8 {
                // 8 chunks: a full address.
                rand_partial_ipv6_addr_with(rng, 8)
            } else {
                // r' <- randomRIO (1, 8 - r)
                let r_prime = rng.next_range(1, 8 - r);
                match r + r_prime {
                    // 7 random chunks plus a single zero chunk.
                    7 => {
                        let mut tks = rand_partial_ipv6_addr_with(rng, r as usize);
                        tks.push(Ipv6AddrToken::Colon);
                        tks.push(Ipv6AddrToken::AllZeros);
                        tks.push(Ipv6AddrToken::Colon);
                        tks.extend(rand_partial_ipv6_addr_with(rng, r_prime as usize));
                        tks
                    }
                    // 8 chunks: a full address.
                    8 => rand_partial_ipv6_addr_with(rng, 8),
                    // The missing chunks are compressed with "::".
                    _ => {
                        let mut tks = rand_partial_ipv6_addr_with(rng, r as usize);
                        tks.push(Ipv6AddrToken::DoubleColon);
                        tks.extend(rand_partial_ipv6_addr_with(rng, r_prime as usize));
                        tks
                    }
                }
            }
        }
        // With a prefix, the remaining chunks are drawn to complete it.
        Some(p) => {
            // let tks = fromJust (maybeIPv6AddrTokens p)
            let mut tks = ipv6_addr_tokens(p)?;
            // countChunks: number of 16-Bit chunks and of "::".
            let (chunks, double_colons) =
                tks.iter()
                    .fold((0usize, 0usize), |(c, d), token| match token {
                        Ipv6AddrToken::SixteenBit(_) | Ipv6AddrToken::AllZeros => (c + 1, d),
                        Ipv6AddrToken::DoubleColon => (c, d + 1),
                        _ => (c, d),
                    });
            // The chunks still to draw depend on the compression shape.
            let to_draw = match double_colons {
                0 => 8usize.saturating_sub(chunks),
                1 => 6usize.saturating_sub(chunks),
                _ => 0,
            };
            // guard (ntks > 0)
            if to_draw == 0 {
                return None;
            }
            let rtks = rand_partial_ipv6_addr_with(rng, to_draw);
            // addColon: a trailing 16-Bit chunk asks for a separator.
            if matches!(
                tks.last(),
                Some(Ipv6AddrToken::SixteenBit(_) | Ipv6AddrToken::AllZeros)
            ) {
                tks.push(Ipv6AddrToken::Colon);
            }
            tks.extend(rtks);
            // guard (isIPv6Addr tks')
            if !is_ipv6_addr(&tks) {
                return None;
            }
            let tks = to_double_colon(&from_double_colon(&tks));
            let addr = ipv6_tokens_to_ipv6_addr(&tks);
            return addr;
        }
    };
    ipv6_tokens_to_ipv6_addr(&tks)
}

/// Returns `Some` of the token list of the IPv6 address derived from the
/// given MAC address, or `None` when the text is not a valid MAC address.
///
/// The MAC hexadecimal bytes are joined two by two into three 16-Bit chunks,
/// separated by colons:
///
/// > mac_addr_to_ipv6_addr_tokens("fa:1d:58:cc:95:16") ==
/// >   Some([SixteenBit("fa1d"), Colon, SixteenBit("58cc"), Colon, SixteenBit("9516")])
pub fn mac_addr_to_ipv6_addr_tokens(text: &str) -> Option<Ipv6AddrTokens> {
    let tks = mac_addr(text)?;
    Some(itertools::Itertools::intersperse(tks.into_iter(), Ipv6AddrToken::Colon).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_canonized_ipv6_addr() {
        assert_eq!(
            ipv6_addr("0:0::FFFF:192.0.2.128").map(|a| a.0),
            Some(String::from("::ffff:192.0.2.128"))
        );
    }

    #[test]
    fn parses_a_pure_ipv6_addr() {
        assert_eq!(
            pure_ipv6_addr("::ffff:192.0.2.128").map(|a| a.0),
            Some(String::from("::ffff:c000:280"))
        );
    }

    #[test]
    fn parses_a_full_ipv6_addr() {
        assert_eq!(
            full_ipv6_addr("::ffff:192.0.2.128").map(|a| a.0),
            Some(String::from("0000:0000:0000:0000:0000:ffff:c000:0280"))
        );
    }

    #[test]
    fn returns_none_for_an_unparsable_addr() {
        assert_eq!(ipv6_addr("wrong"), None);
        assert_eq!(ipv6_addr("1.2.3"), None);
        assert_eq!(pure_ipv6_addr(""), None);
        assert_eq!(full_ipv6_addr("0:0:0"), None);
    }

    #[test]
    fn converts_to_an_arpa_name() {
        let addr = Ipv6Addr::from("4321:0:1:2:3:4:567:89ab");
        assert_eq!(
            to_ip6_arpa(&addr),
            Some(String::from(
                "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.IP6.ARPA."
            ))
        );
    }

    #[test]
    fn converts_to_a_unc_path() {
        let addr = Ipv6Addr::from("2001:0DB8:002a:1005:230:48ff:fe73:989d");
        assert_eq!(
            to_unc(&addr),
            Some(String::from(
                "2001-db8-2a-1005-230-48ff-fe73-989d.ipv6-literal.net"
            ))
        );
    }

    #[test]
    fn conversions_return_none_for_a_garbage_addr() {
        let addr = Ipv6Addr::from("no address");
        assert_eq!(to_ip6_arpa(&addr), None);
        assert_eq!(to_unc(&addr), None);
    }

    #[test]
    fn converts_a_mac_addr_to_tokens() {
        let tks = mac_addr_to_ipv6_addr_tokens("fa:1d:58:cc:95:16").unwrap_or_default();
        assert_eq!(tks.len(), 5);
        assert_eq!(tks[0], Ipv6AddrToken::SixteenBit(String::from("fa1d")));
        assert_eq!(tks[1], Ipv6AddrToken::Colon);
        assert_eq!(tks[2], Ipv6AddrToken::SixteenBit(String::from("58cc")));
        assert_eq!(tks[3], Ipv6AddrToken::Colon);
        assert_eq!(tks[4], Ipv6AddrToken::SixteenBit(String::from("9516")));
        assert_eq!(mac_addr_to_ipv6_addr_tokens("fa:1d"), None);
        assert_eq!(mac_addr_to_ipv6_addr_tokens("gg:1d:58:cc:95:16"), None);
    }

    #[test]
    fn partial_addresses_are_seed_deterministic() {
        let mut a = XorShift64Star::with_seed(42);
        let mut b = XorShift64Star::with_seed(42);
        assert_eq!(
            rand_partial_ipv6_addr_with(&mut a, 3),
            rand_partial_ipv6_addr_with(&mut b, 3)
        );
    }

    #[test]
    fn partial_addresses_have_the_expected_shape() {
        let mut rng = XorShift64Star::with_seed(7);
        let tks = rand_partial_ipv6_addr_with(&mut rng, 3);
        assert_eq!(tks.len(), 5);
        assert!(matches!(tks[0], Ipv6AddrToken::SixteenBit(_)));
        assert_eq!(tks[1], Ipv6AddrToken::Colon);
        assert!(matches!(tks[2], Ipv6AddrToken::SixteenBit(_)));
        assert_eq!(tks[3], Ipv6AddrToken::Colon);
        assert!(matches!(tks[4], Ipv6AddrToken::SixteenBit(_)));
        for i in [0, 2, 4] {
            if let Ipv6AddrToken::SixteenBit(chunk) = &tks[i] {
                assert_eq!(chunk.len(), 4);
                assert!(chunk.chars().all(|c| c.is_ascii_hexdigit()));
            }
        }
    }

    #[test]
    fn partial_addresses_out_of_range_are_empty() {
        let mut rng = XorShift64Star::with_seed(7);
        assert!(rand_partial_ipv6_addr_with(&mut rng, 0).is_empty());
        assert!(rand_partial_ipv6_addr_with(&mut rng, 9).is_empty());
    }

    #[test]
    fn a_masked_chunk_is_a_16_bit_chunk() {
        let mut rng = XorShift64Star::with_seed(11);
        match rand_ipv6_addr_chunk_with(&mut rng, "_f__") {
            Ipv6AddrToken::SixteenBit(chunk) => {
                assert!(chunk.contains('f'));
                assert!(chunk.len() <= 4);
                assert!(chunk.chars().all(|c| c.is_ascii_hexdigit()));
            }
            _ => panic!("a masked chunk is always a 16-Bit chunk"),
        }
    }

    #[test]
    fn a_prefix_is_completed_by_random_chunks() {
        let mut rng = XorShift64Star::with_seed(3);
        match rand_ipv6_addr_with_prefix_core(&mut rng, Some("4321:0:1:2:3:4")) {
            Some(addr) => {
                assert!(addr.0.starts_with("4321:0:1:2:3:4:"));
                assert!(ipv6_addr(&addr.0).is_some());
            }
            None => panic!("a 6-chunk prefix must be completable into an address"),
        }
    }

    #[test]
    fn an_uncompletable_prefix_returns_none() {
        let mut rng = XorShift64Star::with_seed(5);
        assert_eq!(
            rand_ipv6_addr_with_prefix_core(&mut rng, Some("1::2::3")),
            None
        );
        assert_eq!(
            rand_ipv6_addr_with_prefix_core(&mut rng, Some("1:2:3:4:5:6:7:8")),
            None
        );
    }

    #[test]
    fn a_random_address_without_prefix_is_valid() {
        let mut rng = XorShift64Star::with_seed(9);
        let addr = rand_ipv6_addr_with_prefix_core(&mut rng, None);
        let addr = match addr {
            Some(addr) => addr,
            None => panic!("a random address must always be produced"),
        };
        assert!(ipv6_addr(&addr.0).is_some());
    }

    #[test]
    fn public_rand_functions_produce_valid_addresses() {
        let addr = rand_ipv6_addr();
        assert!(ipv6_addr(&addr.0).is_some());
        if let Some(addr) = rand_ipv6_addr_with_prefix(Some("4321:0:1:2:3:4")) {
            assert!(addr.0.starts_with("4321:0:1:2:3:4:"));
        }
        assert_eq!(rand_ipv6_addr_with_prefix(Some("::::")), None);
    }
}
