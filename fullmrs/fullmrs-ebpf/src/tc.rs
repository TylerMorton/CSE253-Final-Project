use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::{PerCpuArray, RingBuf},
    programs::TcContext,
};
use aya_log_ebpf::{debug, error, info};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

use crate::utils::*;
use fullmrs_common::dhcp::DhcpHdr;
use fullmrs_common::tc::PacketBuffer;

#[map]
static DATA: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256 KB

#[map]
static BUF: PerCpuArray<PacketBuffer> = PerCpuArray::with_max_entries(1, 0);

pub const DHCP_MAGIC: u32 = 0x63825363;

#[classifier()]
pub fn fullmrs_tc(ctx: TcContext) -> i32 {
    match try_tc_ringbuf(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_tc_ringbuf(ctx: TcContext) -> Result<i32, ()> {
    let ipmacmap_len = match IPMACMAP.get_ptr_mut(0) {
        Some(val) => val,
        None => {
            return Ok(TC_ACT_PIPE);
        }
    };

    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        EtherType::Ipv6 => {
            error!(
                &ctx,
                "WARNING! IPv6 not supported. No protection against malicious networks"
            );
            return Ok(TC_ACT_PIPE);
        }
        EtherType::Arp => {
            error!(&ctx, "ARP not yet supported");
            return Ok(TC_ACT_PIPE);
        }
        _ => {
            error!(&ctx, "Protocol not yet supported");
            return Ok(TC_ACT_PIPE);
        }
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    if ipv4hdr.proto != IpProto::Udp {
        return Ok(TC_ACT_PIPE);
    }
    let udphdr: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
    if u16::from_be(udphdr.source) != 67 || u16::from_be(udphdr.dest) != 68 {
        return Ok(TC_ACT_PIPE);
    }
    let dhcphdr: DhcpHdr = ctx
        .load(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)
        .map_err(|_| ())?;
    if u32::from_be(dhcphdr.magic) != DHCP_MAGIC {
        return Ok(TC_ACT_PIPE);
    }
    debug!(&ctx, "DHCP packet captured");
    let first_opt: [u8; 4] = ctx
        .load(EthHdr::LEN + Ipv4Hdr::LEN + DhcpHdr::LEN)
        .map_err(|_| ())?;
    if first_opt[0] == 0x35 && first_opt[2] == 0x5 {
        let mut chmac: [u8; 6] = [0; 6];
        info!(&ctx, "DHCP ACK discovered.");
        chmac.copy_from_slice(&dhcphdr.chaddr[0..6]);

        if ipmac_exists(chmac) {
            info!(&ctx, "IP Mac mapping exists. No updates");
            return Ok(TC_ACT_PIPE);
        }
        let val: u32 = unsafe { *ipmacmap_len };
        ipmac_insert(chmac, dhcphdr.yiaddr, val).unwrap();
        unsafe {
            *ipmacmap_len = (*ipmacmap_len + 1) % MAX_IPMACMAP_LEN;
        }
    }
    //let _ = DATA.output(&u32::from_be(ipv4hdr.src_addr), 0).unwrap();
    Ok(TC_ACT_PIPE)
}
