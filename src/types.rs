//! IPv6 address data types.

use smallvec::SmallVec;
use std::fmt::{self, Display, Formatter};

/// An IPv6 address as its textual representation.
///
/// Holds the textual representation of an IPv6 address, canonized in
/// conformation with RFC 5952 by the parsing and rewriting functions.
#[derive(Clone, Debug)]
pub struct Ipv6Addr(pub String);

/// Equality compares the addresses themselves: both sides are canonized
/// (RFC 5952 hexadecimal digits, "::" compression and embedded IPv4
/// addresses are resolved through `internals::tok_pure_ipv6_addr` and
/// `internals::tokens_to_ipv6`, the stand-in for the original IPv6 value
/// equality). "::1" is therefore equal to "0:0:0:0:0:0:0:1".
///
/// A wrapped text that cannot be canonized holds no address value; the raw
/// texts are then compared, so that the equality relation stays reflexive.
impl PartialEq for Ipv6Addr {
    fn eq(&self, other: &Self) -> bool {
        let canonical = |text: &str| {
            crate::internals::tok_pure_ipv6_addr(text)
                .and_then(|tks| crate::internals::tokens_to_ipv6(&tks))
        };
        match (canonical(&self.0), canonical(&other.0)) {
            (Some(a), Some(b)) => a == b,
            _ => self.0 == other.0,
        }
    }
}

impl Eq for Ipv6Addr {}

impl Display for Ipv6Addr {
    /// Renders the wrapped text as-is.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for Ipv6Addr {
    fn from(s: String) -> Self {
        Ipv6Addr(s)
    }
}

impl From<&str> for Ipv6Addr {
    fn from(s: &str) -> Self {
        Ipv6Addr(s.to_owned())
    }
}

/// A token of an IPv6 address textual representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ipv6AddrToken {
    /// A four hexadecimal digits group representing a 16-Bit chunk.
    SixteenBit(String),
    /// An all zeros 16-Bit chunk.
    AllZeros,
    /// A separator between 16-Bit chunks.
    Colon,
    /// A double-colon stands for a unique compression of many consecutive
    /// 16-Bit chunks.
    DoubleColon,
    /// An embedded IPv4 address as representation of the last 32-Bit.
    Ipv4Addr(String),
}

/// A sequence of IPv6 address tokens, stored as a [`SmallVec`].
///
/// A fully expanded IPv6 address is made of 8 chunks separated by 7 colons,
/// hence 15 tokens at most (14 when an embedded IPv4 address stands for the
/// last 32-Bit). An inline capacity of 16 tokens therefore avoids any heap
/// allocation in the address rewriting hot paths.
pub type Ipv6AddrTokens = SmallVec<[Ipv6AddrToken; 16]>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_addr_display_renders_wrapped_text() {
        let addr = Ipv6Addr::from("::1");
        assert_eq!(addr.to_string(), "::1");
    }

    #[test]
    fn ipv6_addr_tokens_are_structurally_comparable() {
        let a = Ipv6AddrToken::SixteenBit(String::from("8db8"));
        let b = Ipv6AddrToken::SixteenBit(String::from("8db8"));
        let c = Ipv6AddrToken::AllZeros;
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn fully_expanded_address_fits_inline_without_heap_allocation() {
        let mut tks: Ipv6AddrTokens = SmallVec::new();
        for i in 0..8 {
            if i > 0 {
                tks.push(Ipv6AddrToken::Colon);
            }
            tks.push(Ipv6AddrToken::SixteenBit(format!("{:x}", i)));
        }
        assert_eq!(tks.len(), 15);
        assert!(!tks.spilled());
    }

    #[test]
    fn ipv6_addr_equality_is_canonical() {
        assert_eq!(Ipv6Addr::from("::1"), Ipv6Addr::from("0:0:0:0:0:0:0:1"));
        assert_eq!(Ipv6Addr::from("2001:DB8::1"), Ipv6Addr::from("2001:db8::1"));
        assert_eq!(
            Ipv6Addr::from("::ffff:192.0.2.128"),
            Ipv6Addr::from("::ffff:c000:280")
        );
        assert_ne!(Ipv6Addr::from("::1"), Ipv6Addr::from("::2"));
    }

    #[test]
    fn ipv6_addr_equality_falls_back_to_text_when_unparseable() {
        // Reflexivity must hold even for a wrapped text that is not an
        // IPv6 address.
        let garbage = Ipv6Addr::from("not an address");
        assert_eq!(garbage, garbage);
        assert_ne!(
            Ipv6Addr::from("not an address"),
            Ipv6Addr::from("not another")
        );
    }
}
