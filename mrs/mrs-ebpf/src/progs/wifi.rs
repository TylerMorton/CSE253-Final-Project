use aya_ebpf::{bindings::xdp_action::*, helpers::bpf_redirect, macros::xdp, programs::XdpContext};
use aya_log_ebpf::{debug, error};
use mrs_common::HandoverParams;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::{utils::*, RedirectOpts, IFACE_MAP, MAC_CACHE_MAP, REDIRECT_MAP};

#[xdp]
/// attach this to the plc out interface, we dont care about what happens there
pub fn xdp_wifi(ctx: XdpContext) -> u32 {
    match try_wifi(&ctx) {
        Ok(ret) => ret,

        Err(err) => {
            error!(&ctx, "Something went wrong");
            err
        }
    }
}

fn try_wifi(ctx: &XdpContext) -> Result<u32, u32> {
    let redirect_opts = REDIRECT_MAP.get_ptr_mut(0).ok_or(XDP_PASS)?;

    let ethhdr = ptr_at_mut::<EthHdr>(ctx, 0).ok_or(XDP_PASS)?;
    let ifaces = *IFACE_MAP.get(0).ok_or(XDP_PASS)?;
    let mac_cache = *MAC_CACHE_MAP.get(0).ok_or(XDP_PASS)?;

    // filter for ipv4
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(XDP_PASS),
    };

    let iphdr = ptr_at_mut::<Ipv4Hdr>(ctx, EthHdr::LEN).ok_or(XDP_PASS)?;

    match unsafe { (*iphdr).proto } {
        IpProto::Udp => {
            let udphdr = ptr_at_mut::<UdpHdr>(ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(XDP_PASS)?;

            unsafe {
                // take care of our handove packet, which is supposed to come in as a udp packet on
                // port 4
                if (*udphdr).dest == 4 {
                    let handover =
                        ptr_at::<HandoverParams>(ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)
                            .ok_or(XDP_PASS)?;
                    if (*handover).val == 1 {
                        (*redirect_opts) = RedirectOpts::PLC
                    } else {
                        (*redirect_opts) = RedirectOpts::WIFI
                    }
                    // just going to kill this packet here
                    return Ok(XDP_ABORTED);
                }

                // handle normal udp packets now
                // update checksum before rewriting ip
                update_l4_csum(
                    &mut (*udphdr).check,
                    (*iphdr).src_addr,
                    ifaces.eth_iface.ip,
                    (*udphdr).source,
                    (*udphdr).source,
                )
            }
        }

        IpProto::Tcp => {
            let tcphdr = ptr_at_mut::<TcpHdr>(ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(XDP_PASS)?;

            unsafe {
                update_l4_csum(
                    &mut (*tcphdr).check,
                    (*iphdr).dst_addr,
                    ifaces.eth_iface.ip,
                    (*tcphdr).source,
                    (*tcphdr).source,
                );
            };
        }

        IpProto::Icmp => {}

        _ => return Ok(XDP_PASS),
    };

    // rewrite ip csum and change packet headers
    unsafe {
        update_ipv4_csum(&mut (*iphdr).check, (*iphdr).src_addr, ifaces.eth_iface.ip);

        (*iphdr).src_addr = ifaces.eth_iface.ip;

        // write cached mac address out, (theoretically should send to next router in the hop)
        (*ethhdr).src_addr = mac_cache.addr;

        // redirect straight out to eth0
        debug!(ctx, "sending to eth");
        Ok(bpf_redirect(ifaces.eth_iface.idx, 0) as u32)
    }
}
