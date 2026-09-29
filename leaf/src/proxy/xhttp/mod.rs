//! XHTTP (`transport/internet/splithttp`) as a leaf inbound/outbound pair.
//!
//! The reference implementation lives in Xray-core. This port keeps the parts
//! that go on the wire -- the mode, the request shape, `xPadding`, the decimal
//! sequence framing -- and implements the HTTP/1.1 carrying them by hand,
//! because this crate has no HTTP client or server library. Plaintext XHTTP
//! therefore speaks HTTP/1.1 (Xray's `decideHTTPVersion` returns `"1.1"` for a
//! stream with no TLS in front of it); one request per connection, as Xray's
//! HTTP/1.1 transport does with `DisableKeepAlives`.

pub(crate) mod b64;
pub mod config;
pub(crate) mod h1;
pub(crate) mod stream;
pub(crate) mod xpadding;

#[cfg(feature = "inbound-xhttp")]
pub mod inbound;

#[cfg(feature = "outbound-xhttp")]
pub mod outbound;
