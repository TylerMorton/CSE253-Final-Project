#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};
use aya_log_ebpf::{debug, info};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

use tc_egress_common::DhcpHdr;

#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static IPMACMAP: HashMap<[u8; 6], u32> = HashMap::with_max_entries(100, 0); //TODO: Correct max

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

fn ipmac_exists(mac: [u8; 6]) -> bool {
    unsafe { IPMACMAP.get(&mac).is_some() }
}

fn insert_ipmac(mac: [u8; 6], ip: u32) {
    IPMACMAP.insert(&mac, &ip, 0).unwrap();
}

fn try_tc_egress(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    match ipv4hdr.proto {
        IpProto::Udp => {
            debug!(&ctx, "udp egress!");
            let udphdr: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
            if u16::from_be(udphdr.source) == 67 && u16::from_be(udphdr.dest) == 68 {
                debug!(&ctx, "dhcp egress?");

                let dhcphdr: DhcpHdr = ctx
                    .load(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)
                    .map_err(|_| ())?;
                debug!(
                    &ctx,
                    "magic: {:X} {:X}",
                    dhcphdr.magic,
                    u32::from_be(dhcphdr.magic)
                );
                if u32::from_be(dhcphdr.magic) != 0x63825363 {
                    return Ok(TC_ACT_PIPE);
                }
                debug!(&ctx, "dhcp egress!!!!");
                let first_opt: [u8; 4] = ctx
                    .load(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + DhcpHdr::LEN)
                    .map_err(|_| ())?;
                if first_opt[0] == 0x35 && first_opt[2] == 0x5 {
                    debug!(&ctx, "dhcp egress! Got ack!");
                    let mut chmac: [u8; 6] = [0; 6];
                    chmac.copy_from_slice(&dhcphdr.chaddr[0..6]);
                    if ipmac_exists(chmac) {
                        return Ok(TC_ACT_PIPE);
                    }
                    insert_ipmac(chmac, dhcphdr.yiaddr);
                }
            }
        }
        _ => {}
    }
    let destination = u32::from_be(ipv4hdr.dst_addr);

    let action = if block_ip(destination) {
        TC_ACT_SHOT
    } else {
        TC_ACT_PIPE
    };

    info!(&ctx, "DEST {:i}, ACTION {}", destination, action);

    Ok(action)
}

/*
#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
*/
