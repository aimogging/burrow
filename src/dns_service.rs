//! Built-in DNS service on `(wg_ip, 53/udp)`.
//!
//! Minimal DNS responder — answers A queries using the wgnat host's
//! system resolver via `tokio::net::lookup_host`. Any non-A query type
//! gets a `NotImp` response code so peers see a clean protocol-level
//! answer rather than a silent drop.
//!
//! Wire-format parsing and serialization are delegated to
//! `hickory-proto` (the maintained successor to trust-dns). Dead-code
//! elimination under `[profile.min]`'s LTO keeps the unused parts of
//! the crate from bloating deploy binaries.
//!
//! Scope: A records only. AAAA, CNAME chains, NS/MX/TXT/SRV all return
//! `NotImp`. The host's resolver handles CNAME-to-A follow-through
//! internally, so the final A addresses in the response reflect the
//! full resolution; CNAME records themselves are not preserved.
//! Matches the semantics SOCKS5 hostname resolution gives you.

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::net::Ipv4Addr;

use tokio::net::lookup_host;

/// Standard DNS port.
pub const DNS_PORT: u16 = 53;

const DEFAULT_TTL: u32 = 60;

pub struct DnsResponse {
    pub payload: Vec<u8>,
}

/// Parse a DNS query (UDP payload), answer A queries via the host
/// resolver, and return the serialized response. Returns `None` if the
/// input is so malformed that we can't even build a refusal.
pub async fn handle_query(query_payload: &[u8]) -> Option<DnsResponse> {
    let query = match Message::from_bytes(query_payload) {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(error = %e, "malformed DNS query — dropping");
            return None;
        }
    };

    let mut response = Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(query.op_code());
    response.set_recursion_desired(query.recursion_desired());
    response.set_recursion_available(true);
    response.set_authoritative(false);
    for q in query.queries() {
        response.add_query(q.clone());
    }

    let first_query = query.queries().first();
    let Some(q) = first_query else {
        // No question section. Just echo an empty response with FormErr.
        response.set_response_code(ResponseCode::FormErr);
        return Some(DnsResponse {
            payload: response.to_bytes().ok()?,
        });
    };

    if q.query_type() != RecordType::A || q.query_class() != DNSClass::IN {
        response.set_response_code(ResponseCode::NotImp);
        return Some(DnsResponse {
            payload: response.to_bytes().ok()?,
        });
    }

    let name_str = q.name().to_utf8();
    // hickory's Name.to_utf8() includes a trailing dot; lookup_host
    // handles either form but is tidier without.
    let trimmed = name_str.trim_end_matches('.');
    let addrs = resolve_a(trimmed).await;

    if addrs.is_empty() {
        response.set_response_code(ResponseCode::NXDomain);
        return Some(DnsResponse {
            payload: response.to_bytes().ok()?,
        });
    }

    for addr in addrs {
        let rdata = RData::A(A(addr));
        let rec = Record::from_rdata(q.name().clone(), DEFAULT_TTL, rdata);
        response.add_answer(rec);
    }
    response.set_response_code(ResponseCode::NoError);
    Some(DnsResponse {
        payload: response.to_bytes().ok()?,
    })
}

async fn resolve_a(name: &str) -> Vec<Ipv4Addr> {
    match lookup_host((name, 0u16)).await {
        Ok(iter) => iter
            .filter_map(|sa| match sa {
                std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
                _ => None,
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;

    fn build_query(name: &str, qtype: RecordType) -> Vec<u8> {
        let mut m = Message::new();
        m.set_id(0x1234);
        m.set_recursion_desired(true);
        let mut q = Query::new();
        q.set_name(Name::from_ascii(name).unwrap());
        q.set_query_type(qtype);
        q.set_query_class(DNSClass::IN);
        m.add_query(q);
        m.to_bytes().unwrap()
    }

    #[tokio::test]
    async fn handle_query_resolves_localhost() {
        let bytes = build_query("localhost.", RecordType::A);
        let resp = handle_query(&bytes).await.expect("response");
        let parsed = Message::from_bytes(&resp.payload).unwrap();
        assert_eq!(parsed.response_code(), ResponseCode::NoError);
        assert!(
            !parsed.answers().is_empty(),
            "expected at least one A record for localhost"
        );
        let a = parsed
            .answers()
            .iter()
            .filter_map(|r| match r.data() {
                Some(RData::A(a)) => Some(a.0),
                _ => None,
            })
            .next()
            .expect("A record rdata");
        assert_eq!(a, Ipv4Addr::new(127, 0, 0, 1));
    }

    #[tokio::test]
    async fn handle_query_returns_notimp_for_aaaa() {
        let bytes = build_query("localhost.", RecordType::AAAA);
        let resp = handle_query(&bytes).await.expect("response");
        let parsed = Message::from_bytes(&resp.payload).unwrap();
        assert_eq!(parsed.response_code(), ResponseCode::NotImp);
    }

    #[tokio::test]
    async fn handle_query_nxdomain_for_unknown_tld() {
        let bytes = build_query("this-does-not-exist.invalid.", RecordType::A);
        let resp = handle_query(&bytes).await.expect("response");
        let parsed = Message::from_bytes(&resp.payload).unwrap();
        assert_eq!(parsed.response_code(), ResponseCode::NXDomain);
    }
}
