use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

use crate::utils::*;
use aya_log_ebpf::{debug, error};
use network_types::{
    arp::ArpHdr,
    eth::{EthHdr, EtherType},
};

#[xdp]
pub fn fullmrs_xdp(ctx: XdpContext) -> u32 {
    match try_fullmrs(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_fullmrs(ctx: &XdpContext) -> Result<u32, u32> {
    let ethhdr = ptr_at_mut::<EthHdr>(ctx, 0).ok_or(xdp_action::XDP_PASS)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Arp => {},
        _ => {
            debug!(ctx, "Not supporting this protocol");
            return Ok(xdp_action::XDP_PASS);
        }
    }

    let arphdr = ptr_at_mut::<ArpHdr>(ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    if unsafe { (*arphdr).plen } != 4 {
        error!(ctx, "Only accepting arp using IPv4");
        return Ok(xdp_action::XDP_DROP);
    }
    let oper = u16::from_be(unsafe { (*arphdr).oper });
    if oper != 1 && oper != 2 {
        debug!(ctx, "Only accept ARP request/response ops.");
        return Ok(xdp_action::XDP_DROP);
    }
    if oper == 2 {
        if !ipmac_exists(unsafe { (*arphdr).sha }) {
            debug!(ctx, "ARP - Response dropped, no entry in map.");
            return Ok(xdp_action::XDP_DROP);
        }
        match ipmac_get(unsafe { (*arphdr).sha }) {
            Some(mapip) => {
                if u32::from_be(mapip) != unsafe { u32::from_be_bytes((*arphdr).spa) } {
                    error!(ctx, "MALICIOUS ARP SPOOFING DETECTED");
                    return Ok(xdp_action::XDP_DROP);
                }
                return Ok(xdp_action::XDP_PASS);
            }
            None => {
                debug!(ctx, "ARP - Error fetch entry");
                return Ok(xdp_action::XDP_DROP);
            }
        }
    }

    //info!(&ctx, "received a packet");
    Ok(xdp_action::XDP_PASS)
}
