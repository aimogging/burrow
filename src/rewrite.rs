//! Low-level packet rewrite primitives. The actual stateful destination
//! tracking lives in `crate::nat::NatTable`; this module only provides
//! parsing and in-place IP/transport rewrites with checksum updates.

use std::net::Ipv4Addr;

use anyhow::{bail, Result};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

#[derive(Debug, Clone, Copy)]
pub struct PacketView {
    pub proto: u8,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Parse the 5-tuple from a raw IPv4 packet. Only TCP/UDP are handled
/// here — ICMP doesn't have ports and is handled separately.
pub fn parse_5tuple(packet: &[u8]) -> Result<PacketView> {
    if packet.len() < 20 {
        bail!("packet too short for IPv4 header");
    }
    if (packet[0] >> 4) != 4 {
        bail!("not an IPv4 packet");
    }
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        bail!("invalid IHL or truncated header");
    }
    let proto = packet[9];
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    let (src_port, dst_port) = match proto {
        PROTO_TCP | PROTO_UDP => {
            if packet.len() < ihl + 4 {
                bail!("transport header truncated");
            }
            (
                u16::from_be_bytes([packet[ihl], packet[ihl + 1]]),
                u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]),
            )
        }
        // For ICMP / others we report (0, 0) — caller decides what to do.
        _ => (0, 0),
    };
    Ok(PacketView {
        proto,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    })
}

/// Rewrite the destination IP and recompute affected checksums in place.
/// Returns the previous destination address.
pub fn rewrite_dst_ip(packet: &mut [u8], new_dst: Ipv4Addr) -> Result<Ipv4Addr> {
    let view = parse_5tuple(packet)?;
    let old_dst = view.dst_ip;
    if old_dst == new_dst {
        return Ok(old_dst);
    }
    packet[16..20].copy_from_slice(&new_dst.octets());
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    rewrite_ip_checksum(packet, ihl);
    update_transport_checksum_for_addr_change(packet, ihl, view.proto, old_dst, new_dst)?;
    Ok(old_dst)
}

/// Rewrite the source IP and recompute affected checksums in place.
/// Returns the previous source address.
pub fn rewrite_src_ip(packet: &mut [u8], new_src: Ipv4Addr) -> Result<Ipv4Addr> {
    let view = parse_5tuple(packet)?;
    let old_src = view.src_ip;
    if old_src == new_src {
        return Ok(old_src);
    }
    packet[12..16].copy_from_slice(&new_src.octets());
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    rewrite_ip_checksum(packet, ihl);
    update_transport_checksum_for_addr_change(packet, ihl, view.proto, old_src, new_src)?;
    Ok(old_src)
}

fn rewrite_ip_checksum(packet: &mut [u8], ihl: usize) {
    packet[10] = 0;
    packet[11] = 0;
    let csum = ones_complement_checksum(&packet[..ihl]);
    packet[10..12].copy_from_slice(&csum.to_be_bytes());
}

/// Apply RFC 1624 incremental checksum update for changing an IP address that
/// participates in the TCP/UDP pseudo-header.
fn update_transport_checksum_for_addr_change(
    packet: &mut [u8],
    ihl: usize,
    proto: u8,
    old_addr: Ipv4Addr,
    new_addr: Ipv4Addr,
) -> Result<()> {
    let csum_offset = match proto {
        PROTO_TCP => Some(ihl + 16), // TCP checksum field
        PROTO_UDP => Some(ihl + 6),  // UDP checksum field
        PROTO_ICMP => None,          // ICMP checksum doesn't include IP fields
        _ => None,
    };
    let Some(off) = csum_offset else {
        return Ok(());
    };
    if packet.len() < off + 2 {
        bail!("transport header too short for checksum update");
    }
    // UDP checksum value of 0 means "unchecked" — leave it alone.
    if proto == PROTO_UDP && packet[off] == 0 && packet[off + 1] == 0 {
        return Ok(());
    }
    let old_csum = u16::from_be_bytes([packet[off], packet[off + 1]]);
    let new_csum = incremental_addr_update(old_csum, old_addr, new_addr);
    packet[off..off + 2].copy_from_slice(&new_csum.to_be_bytes());
    Ok(())
}

/// RFC 1624 incremental checksum update. Treats the 4-byte address as two
/// 16-bit words.
fn incremental_addr_update(old_csum: u16, old_addr: Ipv4Addr, new_addr: Ipv4Addr) -> u16 {
    let old = old_addr.octets();
    let new = new_addr.octets();
    let old_words = [
        u16::from_be_bytes([old[0], old[1]]),
        u16::from_be_bytes([old[2], old[3]]),
    ];
    let new_words = [
        u16::from_be_bytes([new[0], new[1]]),
        u16::from_be_bytes([new[2], new[3]]),
    ];
    // ~HC' = ~HC + ~m + m'   (per RFC 1624 eqn 3)
    let mut sum: u32 = (!old_csum) as u32;
    for w in old_words {
        sum += (!w) as u32;
    }
    for w in new_words {
        sum += w as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn ones_complement_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal IPv4+TCP SYN packet with a real checksum.
    fn build_tcp_syn(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 40]; // 20 IP + 20 TCP, no payload
        // IP header
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes()); // total length
        pkt[8] = 64; // TTL
        pkt[9] = PROTO_TCP;
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());
        rewrite_ip_checksum(&mut pkt, 20);
        // TCP header
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes()); // src port
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes()); // dst port
        pkt[24..28].copy_from_slice(&1234u32.to_be_bytes()); // seq
        pkt[32] = 0x50; // data offset = 5 (20 bytes), reserved = 0
        pkt[33] = 0x02; // SYN flag
        pkt[34..36].copy_from_slice(&65535u16.to_be_bytes()); // window
        // Compute TCP checksum from scratch (pseudo-header + TCP segment)
        let tcp_csum = compute_tcp_checksum(&pkt);
        pkt[36..38].copy_from_slice(&tcp_csum.to_be_bytes());
        pkt
    }

    fn compute_tcp_checksum(pkt: &[u8]) -> u16 {
        // pseudo-header: src(4) + dst(4) + zero(1) + proto(1) + tcp_len(2)
        let tcp_len = (pkt.len() - 20) as u16;
        let mut buf = Vec::new();
        buf.extend_from_slice(&pkt[12..16]); // src
        buf.extend_from_slice(&pkt[16..20]); // dst
        buf.push(0);
        buf.push(PROTO_TCP);
        buf.extend_from_slice(&tcp_len.to_be_bytes());
        buf.extend_from_slice(&pkt[20..]);
        // zero out checksum field within tcp portion
        let csum_idx = buf.len() - (pkt.len() - 20) + 16;
        buf[csum_idx] = 0;
        buf[csum_idx + 1] = 0;
        ones_complement_checksum(&buf)
    }

    fn verify_ip_checksum_zero(pkt: &[u8]) -> bool {
        let ihl = ((pkt[0] & 0x0F) as usize) * 4;
        ones_complement_checksum(&pkt[..ihl]) == 0
    }

    fn verify_tcp_checksum_zero(pkt: &[u8]) -> bool {
        let tcp_len = (pkt.len() - 20) as u16;
        let mut buf = Vec::new();
        buf.extend_from_slice(&pkt[12..16]);
        buf.extend_from_slice(&pkt[16..20]);
        buf.push(0);
        buf.push(PROTO_TCP);
        buf.extend_from_slice(&tcp_len.to_be_bytes());
        buf.extend_from_slice(&pkt[20..]);
        ones_complement_checksum(&buf) == 0
    }

    #[test]
    fn parses_tcp_5tuple() {
        let pkt = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            80,
        );
        let view = parse_5tuple(&pkt).unwrap();
        assert_eq!(view.proto, PROTO_TCP);
        assert_eq!(view.src_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(view.dst_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(view.src_port, 54321);
        assert_eq!(view.dst_port, 80);
    }

    #[test]
    fn dst_rewrite_updates_ip_and_tcp_checksums() {
        let mut pkt = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            80,
        );
        assert!(verify_ip_checksum_zero(&pkt));
        assert!(verify_tcp_checksum_zero(&pkt));

        let old = rewrite_dst_ip(&mut pkt, Ipv4Addr::new(10, 0, 0, 2)).unwrap();
        assert_eq!(old, Ipv4Addr::new(192, 168, 1, 50));

        // Both checksums must remain valid after the rewrite.
        assert!(verify_ip_checksum_zero(&pkt));
        assert!(verify_tcp_checksum_zero(&pkt));

        let view = parse_5tuple(&pkt).unwrap();
        assert_eq!(view.dst_ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(view.src_ip, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn src_rewrite_updates_ip_and_tcp_checksums() {
        let mut pkt = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            80,
            54321,
        );
        assert!(verify_ip_checksum_zero(&pkt));
        assert!(verify_tcp_checksum_zero(&pkt));

        rewrite_src_ip(&mut pkt, Ipv4Addr::new(192, 168, 1, 50)).unwrap();

        assert!(verify_ip_checksum_zero(&pkt));
        assert!(verify_tcp_checksum_zero(&pkt));
        let view = parse_5tuple(&pkt).unwrap();
        assert_eq!(view.src_ip, Ipv4Addr::new(192, 168, 1, 50));
    }

    #[test]
    fn udp_checksum_zero_left_unchecked() {
        // Build a UDP packet with checksum=0 and verify rewrite does NOT touch it.
        let mut pkt = vec![0u8; 28]; // 20 IP + 8 UDP
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = PROTO_UDP;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[192, 168, 1, 50]);
        rewrite_ip_checksum(&mut pkt, 20);
        pkt[20..22].copy_from_slice(&53u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&53u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&8u16.to_be_bytes()); // udp length
        // checksum left at 0,0 (valid for IPv4 UDP — means no checksum)

        rewrite_dst_ip(&mut pkt, Ipv4Addr::new(10, 0, 0, 2)).unwrap();
        assert_eq!(&pkt[26..28], &[0, 0], "UDP checksum 0 must remain 0");
        assert!(verify_ip_checksum_zero(&pkt));
    }

    #[test]
    fn rejects_non_ipv4() {
        let pkt = vec![0x60u8; 40]; // IPv6 first nibble
        let err = parse_5tuple(&pkt).unwrap_err();
        assert!(err.to_string().contains("not an IPv4"));
    }

    #[test]
    fn rejects_truncated() {
        let pkt = vec![0x45u8, 0, 0, 10];
        let err = parse_5tuple(&pkt).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }
}
