use aya_ebpf::{bindings::{xdp_action, xdp_action::XDP_PASS}, macros::xdp, programs::XdpContext};
use aya_log_ebpf::{debug, error};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};


use crate::{utils::*, RedirectOpts, IFACE_MAP, MAC_CACHE_MAP, REDIRECT_MAP};

#[xdp]
/// attach this to the plc out interface, we dont care about what happens there
pub fn xdp_plc(ctx: XdpContext) -> u32 {
    match try_plc(&ctx) {
        Ok(ret) => ret,

        Err(err) => {
            error!(&ctx, "Something went wrong");
            err
        }
    }
}

fn try_plc(ctx: &XdpContext) -> Result<u32, u32> {
    let redirect_opts = REDIRECT_MAP.get_ptr_mut(0).ok_or(XDP_PASS)?;
    let ethhdr = ptr_at_mut::<EthHdr>(ctx, 0).ok_or(XDP_PASS)?;
    let ifaces = *IFACE_MAP.get(0).ok_or(XDP_PASS)?;
    let mac_cache = *MAC_CACHE_MAP.get(0).ok_or(XDP_PASS)?;

    match unsafe {(*ethhdr).ether_type} {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let iphdr = ptr_at_mut::<Ipv4Hdr>(ctx, EthHdr::LEN).ok_or(XDP_PASS)?;
    
    match unsafe {(*iphdr).proto} {
        IpProto::Udp => {
            let udphdr = ptr_at_mut::<UdpHdr>(ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(XDP_PASS)?;
            unsafe {
            update_l4_csum(
                &mut (*udphdr).check,
                (*iphdr).src_addr,
                ifaces.eth_iface.ip,
                (*udphdr).source,
                (*udphdr).source,
                )
            }
        },
        IpProto::Tcp => {
            let tcphdr = ptr_at_mut::<TcpHdr>(ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(XDP_PASS)?;
            unsafe {
            update_l4_csum(
                &mut (*tcphdr).check,
                (*iphdr).src_addr,
                ifaces.eth_iface.ip,
                (*tcphdr).source,
                (*tcphdr).source,
                )
            }
        },
        IpProto::Icmp => {}
        _ => {
            debug!(ctx, "L3/4 Proto not handled. Passing.");
            return Ok(XDP_PASS);
        }
    }


    Ok(xdp_action::XDP_PASS)
}
