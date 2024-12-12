#![no_std]
#![no_main]

use aya_ebpf::{bindings::{TC_ACT_OK, TC_ACT_SHOT}, macros::classifier, programs::TcContext};
use aya_log_ebpf::{info, debug};

use network_types::{
    eth::{EtherType, EthHdr},
    ip::{Ipv4Hdr, IpProto},
    udp::UdpHdr,
};
mod ptrs;
mod dhcp;
use dhcp::DhcpHdr;

pub const DHCP_MAGIC: u32 = 0x63825363;

#[classifier]
pub fn anti_arp_spoof(ctx: TcContext) -> i32 {
    match try_anti_arp_spoof(&ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_anti_arp_spoof(ctx: &TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4  => {},
        _ => {
            return Ok(TC_ACT_OK); }
    }
    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    if ipv4hdr.proto != IpProto::Udp {
        return Ok(TC_ACT_OK);
    }
    let udphdr: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
    if (u16::from_be(udphdr.source) != 67 || u16::from_be(udphdr.dest) != 68) {
        debug!(ctx, "Not correct udp ports");
        return Ok(TC_ACT_OK);
    }
    let dhcphdr: DhcpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN).map_err(|_| ())?;
    if u32::from_be(dhcphdr.magic) != DHCP_MAGIC {
        return Ok(TC_ACT_OK);
    }
    debug!(ctx, "sending dhcp packet");
    let first_opt: [u8; 4] = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + DhcpHdr::LEN).map_err(|_| ())?;
    if (first_opt[0] != 0x35 || first_opt[2] != 0x5) {
        return Ok(TC_ACT_OK);
    }
    let mut chmac: [u8; 6] = [0; 6];
    chmac.copy_from_slice(&dhcphdr.chaddr[0..6]);
    debug!(ctx, "mac registered: {:X}{:X}{:X}{:X}{:X}{:X}", chmac[0], chmac[1], chmac[2], chmac[3], chmac[4], chmac[5]);
    Ok(TC_ACT_OK)
}


#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
