//! Parsing and writing IPv6 addresses in accordance with
//! [RFC 4291](https://datatracker.ietf.org/doc/html/rfc4291) and
//! [RFC 5952](https://datatracker.ietf.org/doc/html/rfc5952).

pub mod types;

pub(crate) mod internals;

mod functions;

pub use functions::{
    full_ipv6_addr, ipv6_addr, mac_addr_to_ipv6_addr_tokens, pure_ipv6_addr, rand_ipv6_addr,
    rand_ipv6_addr_chunk, rand_ipv6_addr_with_prefix, rand_partial_ipv6_addr, to_ip6_arpa, to_unc,
};

pub use types::{Ipv6Addr, Ipv6AddrToken, Ipv6AddrTokens};
