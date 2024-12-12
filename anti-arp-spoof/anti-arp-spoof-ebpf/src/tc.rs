#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    macros::{
        classifier,
        map
    }, programs::TcContext,
    maps::Array
};
use aya_log_ebpf::debug;
use anti_arp_spoof_common::Client;
use network_types::{
    eth::{EtherType, EthHdr},
    ip::{Ipv4Hdr, IpProto},
    udp::UdpHdr,
};
use crate::dhcp::DhcpHdr;

pub const DHCP_MAGIC: u32 = 0x63825363;

#[map]
pub static CLIENTS: Array<Client> = Array::with_max_entries(100, 0);

#[map]
pub static CLIENTS_SIZE: Array<u32> = Array::with_max_entries(1, 0);

#[classifier]
pub fn anti_arp_spoof(ctx: TcContext) -> i32 {
    match try_anti_arp_spoof(&ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_anti_arp_spoof(ctx: &TcContext) -> Result<i32, i32> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| TC_ACT_OK)?;
    match ethhdr.ether_type {
        EtherType::Ipv4  => {},
        _ => {
            return Ok(TC_ACT_OK); }
    }
    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| TC_ACT_OK)?;
    if ipv4hdr.proto != IpProto::Udp {
        return Ok(TC_ACT_OK);
    }
    let udphdr: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| TC_ACT_OK)?;
    if u16::from_be(udphdr.source) != 67 || u16::from_be(udphdr.dest) != 68 {
        debug!(ctx, "Not correct udp ports");
        return Ok(TC_ACT_OK);
    }
    let dhcphdr: DhcpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN).map_err(|_| TC_ACT_OK)?;
    if u32::from_be(dhcphdr.magic) != DHCP_MAGIC {
        return Ok(TC_ACT_OK);
    }
    debug!(ctx, "sending dhcp packet");
    let first_opt: [u8; 4] = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + DhcpHdr::LEN).map_err(|_| TC_ACT_OK)?;
    if first_opt[0] != 0x35 || first_opt[2] != 0x5 {
        return Ok(TC_ACT_OK);
    }
    let mut chmac: [u8; 6] = [0; 6];
    chmac.copy_from_slice(&dhcphdr.chaddr[0..6]);
    debug!(ctx, "mac registered: {:X}{:X}{:X}{:X}{:X}{:X}", chmac[0], chmac[1], chmac[2], chmac[3], chmac[4], chmac[5]);
    let clients_size = CLIENTS_SIZE.get_ptr_mut(0).ok_or(TC_ACT_OK)?;
    debug!(ctx, "{}", unsafe {*clients_size } );
    let clients_size = CLIENTS_SIZE.get_ptr_mut(0).ok_or(TC_ACT_OK)?;
    if unsafe {*clients_size} > 100 {
        debug!(ctx, "client list full");
        return Ok(TC_ACT_OK);
    }
    let client = unsafe {CLIENTS.get_ptr_mut(*clients_size).ok_or(TC_ACT_OK)?};
    unsafe {(*client).mac = chmac};
    unsafe {(*client).ip = dhcphdr.yiaddr}
    debug!(ctx, "added to table");
    Ok(TC_ACT_OK)
}


