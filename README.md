# ipv6addr [![CI](https://github.com/MichelBoucey/ipv6addr-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/MichelBoucey/ipv6addr-rs/actions/workflows/ci.yml)

`ipv6addr` is a `Rust library` (ported from [the Haskell library IPv6Addr](https://github.com/MichelBoucey/IPv6Addr)) to deal with IPv6 address text representations, canonization and manipulations. See the [full documentation](https://docs.rs/ipv6addr/latest/ipv6addr/).

* Canonical, in conformation with [RFC 5952](https://www.rfc-editor.org/rfc/rfc5952)
* Pure, *i.e.* force the rewriting of IPv4 address if present
* Full length
* Reverse lookup domain name, in conformation with [RFC 3596 Section 2.5](https://www.rfc-editor.org/rfc/rfc3596#section-2.5)
* Windows UNC path name
* Random generation for test purpose

*P.S.* : You can try/use `ipv6addr` through the CLI tool [ip6addr]( https://hackage.haskell.org/package/ip6addr ).

