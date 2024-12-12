use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

use aya_log_ebpf::debug;
use network_types::{
    arp::ArpHdr,
    eth::{EthHdr, EtherType},
};

use crate::ptrs::ptr_at_mut;
use crate::tc::{CLIENTS, CLIENTS_SIZE};

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
        debug!(ctx, "Only accepting arp using IPv4");
        return Ok(xdp_action::XDP_PASS);
    }
    let oper = u16::from_be(unsafe { (*arphdr).oper });
    if oper != 1 && oper != 2 {
        return Ok(xdp_action::XDP_PASS);
    }
    if oper == 2 {
        let client_size = CLIENTS_SIZE.get_ptr(0).ok_or(xdp_action::XDP_PASS)?;
        for i in 0..unsafe {*client_size} {
            let client = CLIENTS.get_ptr(i).ok_or(xdp_action::XDP_PASS)?;
            unsafe { if (*client).ip == u32::from_be_bytes((*arphdr).spa) && (*client).mac != (*arphdr).sha {
                debug!(ctx, "SPOOFING DETECTED!");
                return Ok(xdp_action::XDP_DROP);
            }
            }
        }
    }
    Ok(xdp_action::XDP_PASS)
}
