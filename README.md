# ipv6addr [![CI](https://github.com/MichelBoucey/ipv6addr-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/MichelBoucey/ipv6addr-rs/actions/workflows/ci.yml)

`ipv6addr` is a `Rust library` (ported from [the Haskell library IPv6Addr](https://github.com/MichelBoucey/IPv6Addr)) to deal with IPv6 address textual representations, canonization and manipulations. See the [full documentation](https://docs.rs/ipv6addr/latest/ipv6addr/).

* Canonical IPv6 address, in conformation with [RFC 5952](https://www.rfc-editor.org/rfc/rfc5952)
* Pure IPv6 address, *i.e.* force the rewriting of IPv4 address if present
* IPv6 address full length
* Reverse lookup domain name `IP6.ARPA.` address, in conformation with [RFC 3596 Section 2.5](https://www.rfc-editor.org/rfc/rfc3596#section-2.5)
* IPv6 address conversion to `Windows UNC path name`
* IPv6 address conversion to and from the core Rust library `std::net::Ipv6Addr`
* IPv6 address random generation for test purpose

*P.S.* : You can try/use `ipv6addr` through the CLI tool [ip6addr]( https://hackage.haskell.org/package/ip6addr ).

