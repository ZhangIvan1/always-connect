//! Authentication response framing. Headers must be inspected before any byte
//! reaches openconnect; otherwise it can follow a redirect outside the relay.
use crate::relay::{Chunks, FramingError};

const LIMIT: usize = 131_072;

#[derive(Default)]
enum Body {
    #[default]
    Header,
    Fixed(usize),
    UntilClose,
    ChunkSize,
    Chunk(usize),
    ChunkEnd(usize),
    Trailers,
}

#[derive(Default)]
pub struct Responses {
    pending: Vec<u8>,
    body: Body,
    authority: Option<(String, u16)>,
    blocked: bool,
    redirect: Option<(u16, String)>,
    trailer_bytes: usize,
}

impl Responses {
    pub fn set_target(&mut self, host: &str, port: u16) {
        self.authority = Some((host.to_ascii_lowercase(), port));
    }

    pub fn take_redirect(&mut self) -> Option<(u16, String)> {
        self.redirect.take()
    }

    fn safe_location(&self, location: &str) -> bool {
        // A single leading slash is an origin-relative reference. Backslashes,
        // controls and ambiguous URI forms are never handed to another parser.
        if location.bytes().any(|b| b <= 32 || b >= 127 || b == b'\\') {
            return false;
        }
        if location.starts_with('/') && !location.starts_with("//") {
            return true;
        }
        let rest = if let Some(rest) = location.strip_prefix("//") {
            rest
        } else if location
            .get(..8)
            .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
        {
            &location[8..]
        } else {
            // Relative paths cannot have a scheme in their first segment.
            return !location.split('/').next().unwrap_or("").contains(':');
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.is_empty() || authority.contains('@') || authority.contains(['[', ']']) {
            return false;
        }
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => match port.parse::<u16>() {
                Ok(port) if port > 0 => (host, port),
                _ => return false,
            },
            None => (authority, 443),
        };
        self.authority
            .as_ref()
            .is_some_and(|(h, p)| host.eq_ignore_ascii_case(h) && port == *p)
    }

    /// Processes HTTP only. The caller keeps CSTP CONNECT / tunnel framing.
    /// Body bytes stream through; only a header or chunk metadata is buffered.
    pub fn feed(&mut self, mut bytes: &[u8], out: &mut Chunks) -> Result<(), FramingError> {
        if self.blocked {
            return Err(FramingError::Redirect);
        }
        while !bytes.is_empty() {
            match self.body {
                Body::UntilClose => {
                    out.push(bytes);
                    return Ok(());
                }
                Body::Fixed(ref mut remaining) | Body::Chunk(ref mut remaining) => {
                    let n = (*remaining).min(bytes.len());
                    out.push(&bytes[..n]);
                    bytes = &bytes[n..];
                    *remaining -= n;
                    if *remaining == 0 {
                        self.body = if matches!(self.body, Body::Chunk(_)) {
                            Body::ChunkEnd(0)
                        } else {
                            Body::Header
                        };
                    }
                }
                Body::ChunkEnd(ref mut seen) => {
                    if bytes[0] != b"\r\n"[*seen] {
                        return Err(FramingError::Invalid);
                    }
                    self.pending.push(bytes[0]);
                    bytes = &bytes[1..];
                    *seen += 1;
                    if *seen == 2 {
                        out.push(&self.pending);
                        self.pending.clear();
                        self.body = Body::ChunkSize;
                    }
                }
                _ => {
                    // Append only up to the boundary, never an entire read's
                    // body: a small header with a large body stays valid.
                    self.pending.push(bytes[0]);
                    bytes = &bytes[1..];
                    if self.pending.len() > LIMIT {
                        return Err(FramingError::Oversized);
                    }
                    let boundary = match self.body {
                        Body::Header => self.pending.ends_with(b"\r\n\r\n"),
                        _ => self.pending.ends_with(b"\r\n"),
                    };
                    if !boundary {
                        continue;
                    }
                    match self.body {
                        Body::Header => self.header()?,
                        Body::ChunkSize => {
                            let text = std::str::from_utf8(&self.pending)
                                .map_err(|_| FramingError::Invalid)?;
                            let number = text
                                .trim_end_matches("\r\n")
                                .split(';')
                                .next()
                                .unwrap_or("");
                            if number.is_empty() || !number.bytes().all(|b| b.is_ascii_hexdigit()) {
                                return Err(FramingError::Invalid);
                            }
                            let n = usize::from_str_radix(number, 16)
                                .map_err(|_| FramingError::Invalid)?;
                            self.body = if n == 0 {
                                Body::Trailers
                            } else {
                                Body::Chunk(n)
                            };
                        }
                        Body::Trailers => {
                            self.trailer_bytes += self.pending.len();
                            if self.trailer_bytes > LIMIT {
                                return Err(FramingError::Oversized);
                            }
                            if self.pending == b"\r\n" {
                                self.body = Body::Header;
                                self.trailer_bytes = 0;
                            } else {
                                let line = std::str::from_utf8(&self.pending)
                                    .map_err(|_| FramingError::Invalid)?;
                                let (name, _) =
                                    line.split_once(':').ok_or(FramingError::Invalid)?;
                                if !valid_name(name)
                                    || matches!(
                                        name.to_ascii_lowercase().as_str(),
                                        "location" | "content-length" | "transfer-encoding"
                                    )
                                {
                                    return Err(FramingError::Invalid);
                                }
                            }
                        }
                        _ => unreachable!(),
                    }
                    out.push(&self.pending);
                    self.pending.clear();
                }
            }
        }
        Ok(())
    }

    fn header(&mut self) -> Result<(), FramingError> {
        let text = String::from_utf8_lossy(&self.pending);
        let mut lines = text.split("\r\n");
        let mut status = lines.next().unwrap_or("").split_whitespace();
        if !matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
            return Err(FramingError::Invalid);
        }
        let code = status
            .next()
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or(FramingError::Invalid)?;
        if !(100..600).contains(&code) {
            return Err(FramingError::Invalid);
        }
        let mut length = None;
        let mut chunked = false;
        let mut location = None;
        for line in lines.filter(|l| !l.is_empty()) {
            if line.starts_with([' ', '\t']) {
                return Err(FramingError::Invalid);
            }
            let (name, value) = line.split_once(':').ok_or(FramingError::Invalid)?;
            if !valid_name(name) {
                return Err(FramingError::Invalid);
            }
            let value = value.trim();
            match name.to_ascii_lowercase().as_str() {
                "content-length" => {
                    if length.is_some() || !value.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(FramingError::Invalid);
                    }
                    length = Some(value.parse::<usize>().map_err(|_| FramingError::Invalid)?);
                }
                "transfer-encoding" => {
                    if chunked || !value.eq_ignore_ascii_case("chunked") {
                        return Err(FramingError::Invalid);
                    }
                    chunked = true;
                }
                "location" => {
                    if location.replace(value).is_some() {
                        return Err(FramingError::Invalid);
                    }
                }
                _ => {}
            }
        }
        if chunked && length.is_some() {
            return Err(FramingError::Invalid);
        }
        if (300..400).contains(&code) && location.is_some_and(|l| !self.safe_location(l)) {
            self.blocked = true;
            self.redirect = location.map(|l| (code, l.to_string()));
            return Err(FramingError::Redirect);
        }
        self.body = if (100..200).contains(&code) || code == 204 || code == 304 || length == Some(0)
        {
            if code == 101 {
                return Err(FramingError::Invalid);
            }
            Body::Header
        } else if chunked {
            Body::ChunkSize
        } else if let Some(n) = length {
            Body::Fixed(n)
        } else {
            Body::UntilClose
        };
        Ok(())
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parser() -> Responses {
        let mut p = Responses::default();
        p.set_target("vpn-a.example", 6443);
        p
    }
    #[test]
    fn redirect_never_escapes_at_any_split() {
        let wire = b"HTTP/1.1 302 Found\r\nLocation: https://vpn-b.example:6443/\r\nContent-Length: 4\r\n\r\nbody";
        for split in 0..wire.len() {
            let mut p = parser();
            let mut out = Chunks::default();
            let first = p.feed(&wire[..split], &mut out);
            if first.is_ok() {
                assert_eq!(
                    p.feed(&wire[split..], &mut out),
                    Err(FramingError::Redirect)
                );
            } else {
                assert_eq!(first, Err(FramingError::Redirect));
            }
            assert!(out.is_empty());
            assert_eq!(p.feed(b"more", &mut out), Err(FramingError::Redirect));
        }
    }
    #[test]
    fn body_and_interim_boundaries() {
        for body in [
            "Content-Length: 4\r\n\r\nbody",
            "Transfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n",
        ] {
            let wire = format!("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n{body}HTTP/1.1 302 Found\r\nLocation: //vpn-b.example:6443/\r\n\r\n");
            let mut p = parser();
            let mut out = Chunks::default();
            for byte in wire.as_bytes() {
                if p.feed(&[*byte], &mut out).is_err() {
                    break;
                }
            }
            let sent = out.to_vecs().concat();
            assert!(!String::from_utf8_lossy(&sent).contains("302"));
            assert_eq!(p.feed(b"x", &mut out), Err(FramingError::Redirect));
        }
    }
    #[test]
    fn same_origin_and_relative_only() {
        let p = parser();
        for value in [
            "/login",
            "login?next=x",
            "HTTPS://VPN-A.EXAMPLE:6443/login",
            "//vpn-a.example:6443/x",
        ] {
            assert!(p.safe_location(value), "{value}");
        }
        for value in [
            "https://vpn-a.example/x",
            "http://vpn-a.example:6443/x",
            "//vpn-b.example:6443",
            "https://user@vpn-a.example:6443/",
            "https:\\evil",
            "//",
            "//vpn-a.example:0/",
        ] {
            assert!(!p.safe_location(value), "{value}");
        }
    }
    #[test]
    fn oversized_headers_and_large_bodies() {
        let mut p = parser();
        let mut out = Chunks::default();
        assert_eq!(
            p.feed(&vec![b'x'; LIMIT + 1], &mut out),
            Err(FramingError::Oversized)
        );
        let mut p = parser();
        let mut out = Chunks::default();
        let mut bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 200000\r\n\r\n".to_vec();
        bytes.extend(vec![b'x'; 200000]);
        p.feed(&bytes, &mut out).unwrap();
        assert_eq!(out.to_vecs().concat(), bytes);
    }
}

#[cfg(test)]
mod malformed_tests {
    use super::*;
    #[test]
    fn ambiguous_framing_is_not_forwarded() {
        for fields in [
            "Location : https://vpn-b.example/",
            "Location: /a\r\nLocation: /b",
            "Content-Length: 1\r\nContent-Length: 1",
            "Content-Length: 1\r\nTransfer-Encoding: chunked",
            " Location: /a",
            "Transfer-Encoding: gzip",
        ] {
            let mut parser = Responses::default();
            let mut out = Chunks::default();
            assert!(parser
                .feed(
                    format!("HTTP/1.1 302 Found\r\n{fields}\r\n\r\n").as_bytes(),
                    &mut out
                )
                .is_err());
            assert!(out.is_empty());
        }
    }
    #[test]
    fn same_origin_response_is_byte_exact() {
        let wire = b"HTTP/1.1 302 Found\r\nLocation: https://vpn-a.example:6443/login\r\nContent-Length: 4\r\n\r\nbody";
        let mut parser = Responses::default();
        parser.set_target("vpn-a.example", 6443);
        let mut out = Chunks::default();
        for byte in wire {
            parser.feed(&[*byte], &mut out).unwrap();
        }
        assert_eq!(out.to_vecs().concat(), wire);
    }
}
