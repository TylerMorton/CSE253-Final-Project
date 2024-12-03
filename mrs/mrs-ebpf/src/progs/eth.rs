use core::u32;

use aya_ebpf::{
    bindings::xdp_action::{self, XDP_PASS},
    helpers::bpf_redirect,
    macros::xdp,
    programs::XdpContext,
};
use aya_log_ebpf::{debug, error, info};
use network_types::{
    arp::ArpHdr,
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use core::mem;

#[repr(C)]
pub struct DhcpHdr {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: u32,
    pub yiaddr: u32,
    pub siaddr: u32,
    pub giaddr: u32,
    pub chaddr: [u8; 16],
    pub sname: [u8;64],
    pub file: [u8; 128],
    pub magic: u32,
}
impl DhcpHdr {
    pub const LEN: usize = mem::size_of::<DhcpHdr>();
}

// TODO:
pub struct DhcpOption {}

use mrs_common::{HandoverHdr, HandoverMode, MediumSelection, UserParams};

use crate::{
    utils::*, ARP_CACHE_MAP, ARP_CLIENT_REQUESTS, CLIENT_MAP, HANDOVER_MAP, IFACE_MAP, IPMAC_MAP,
    MAC_CACHE_MAP, USER_PARAMS_MAP,
};

// -- attach this to the program we want to redirect from
#[xdp]
pub fn xdp_eth(ctx: XdpContext) -> u32 {
    match try_eth(&ctx) {
        Ok(ret) => ret,
        Err(err) => {
            error!(&ctx, "Something went wrong");
            err
        }
    }
}

fn generate_arp_resp(arphdr: *mut ArpHdr, mac: [u8; 6], srcip: u32) -> ArpHdr {
    ArpHdr {
        htype: 1_u16.to_be(),
        ptype: 0x0800_u16.to_be(),
        hlen: 6,
        plen: 4,
        oper: 2_u16.to_be(),
        sha: mac,
        spa: srcip.to_be_bytes(),
        tha: unsafe { (*arphdr).sha },
        tpa: unsafe { (*arphdr).spa },
    }
}

fn try_eth(ctx: &XdpContext) -> Result<u32, u32> {
    let ifaces = *IFACE_MAP.get(0).ok_or(xdp_action::XDP_PASS)?;
    let client = *CLIENT_MAP.get(0).ok_or(xdp_action::XDP_PASS)?;
    let user_params: UserParams = *USER_PARAMS_MAP.get(0).ok_or(xdp_action::XDP_PASS)?;
    let handover_param = *HANDOVER_MAP.get(0).ok_or(xdp_action::XDP_PASS)?;
    let mac_cache = MAC_CACHE_MAP.get_ptr_mut(0).ok_or(XDP_PASS)?;

    let mut medium_selection = MediumSelection::Light;

    let is_auto = match user_params.handover_mode {
        HandoverMode::Auto(medium) => {
            medium_selection = medium;
            true
        }
        HandoverMode::Manual(medium) => {
            medium_selection = medium;
            false
        }
    };

    // grab eth hdr
    let ethhdr = ptr_at_mut::<EthHdr>(ctx, 0).ok_or(xdp_action::XDP_PASS)?;

    // update mac cache
    unsafe {
        // i know its ugly but need to do it this way to get past verifier
        (*mac_cache).addr[0] = (*ethhdr).src_addr[0];
        (*mac_cache).addr[1] = (*ethhdr).src_addr[1];
        (*mac_cache).addr[2] = (*ethhdr).src_addr[2];
        (*mac_cache).addr[3] = (*ethhdr).src_addr[3];
        (*mac_cache).addr[4] = (*ethhdr).src_addr[4];
        (*mac_cache).addr[5] = (*ethhdr).src_addr[5];
    }

    // filter for ipv4
    let ethertype = match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
            EtherType::Ipv4
        },
        EtherType::Arp => EtherType::Arp,
        EtherType::Ipv6 => {
            return Ok(xdp_action::XDP_PASS);
        }
        _ => {
            return Ok(xdp_action::XDP_PASS);
        }
    };

    // ARP shenanigans
    if ethertype == EtherType::Arp {
        //TODO: don't readin any packets with src from host
        return Ok(xdp_action::XDP_PASS);
        let arphdr = ptr_at_mut::<ArpHdr>(ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;

        match unsafe { (*arphdr).plen } {
            4 => {
                debug!(ctx, "arp using ipv4.. nice");
            }
            _ => {
                debug!(ctx, "only accepting arp using ipv4, wtf are you using?");
                return Ok(xdp_action::XDP_DROP);
            }
        }

        if unsafe { (*arphdr).sha } == ifaces.eth_iface.mac {
            error!(
                ctx,
                "WARNING: Potential malicious intent. Not accepting arp packets from MRS source"
            );
            return Ok(xdp_action::XDP_DROP);
        }
        /*
        let mapped_ip = unsafe { IPMAC_MAP.get(&(*arphdr).sha).unwrap() };
        if mapped_id != unsafe { (*arphdr).spa } {
            debug!(ctx, "Dropping potentially unsafe packet");
            return Ok(xdp_action::XDP_DROP);
        }
        */
        let oper = u16::from_be(unsafe { (*arphdr).oper });
        debug!(ctx, "operation: {}", oper);
        if oper != 1 && oper != 2 {
            debug!(ctx, "Only accepting ARP request/response operations");
            return Ok(xdp_action::XDP_DROP);
        }

        if oper == 2 {
            // TODO: check network tuple not just mac
            if unsafe { (*arphdr).tha == ifaces.eth_iface.mac } {
            } else {
                debug!(ctx, "ARP response not destined for MRS. Dropping.");
                return Ok(xdp_action::XDP_DROP);
            }
        }

        //TODO: Is    there performance to use [u8;4] instead of u32 from_be?
        match unsafe { ARP_CACHE_MAP.get(&u32::from_be_bytes((*arphdr).tpa)) } {
            Some(maccache) => {
                debug!(ctx, "ARP cache hit.");
                // Send response
                let arphdr_resp = generate_arp_resp(arphdr, *maccache, ifaces.eth_iface.ip);
                return unsafe {
                    (*arphdr) = arphdr_resp;
                    match medium_selection {
                        MediumSelection::Radio => {
                            debug!(ctx, "sending to plc");
                            unsafe { (*ethhdr).src_addr = ifaces.plc_iface.mac };
                            Ok(bpf_redirect(ifaces.plc_iface.idx, 0) as u32)
                        }
                        MediumSelection::Light => {
                            debug!(ctx, "sending to wifi");
                            Ok(bpf_redirect(ifaces.wifi_iface.idx, 0) as u32)
                        }
                    }
                };
            }
            None => {
                // Do an ARP Broadcast over eth (fwd request but change src)
                debug!(ctx, "ARP cache miss. Forwarding on eth iface.");
                ARP_CLIENT_REQUESTS
                    .insert(
                        &u32::from_be_bytes(unsafe { (*arphdr).tpa }),
                        unsafe { &(*arphdr).sha },
                        0,
                    )
                    .unwrap();
                unsafe {
                    (*arphdr).sha = ifaces.eth_iface.mac;
                    (*arphdr).spa = ifaces.eth_iface.ip.to_be_bytes();
                    return Ok(bpf_redirect(ifaces.eth_iface.idx, 0) as u32);
                }
            }
        };
    }

    let iphdr = ptr_at_mut::<Ipv4Hdr>(ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    
    /*
    if is_auto {
        unsafe {
            let ihl: u8 = (*iphdr).ihl();
            if ihl >= 6 {
                debug!(ctx, "ihl: {}", ihl);
                //NOTE:  Do we want ok_or to pass here? I don't think so.. we want redirects.
                let handover_flag = ptr_at_mut::<HandoverHdr>(ctx, EthHdr::LEN + Ipv4Hdr::LEN)
                    .ok_or(xdp_action::XDP_PASS)?;
                debug!(ctx, "handover flag? {}", (*handover_flag).medium_sel);
                match (*handover_flag).medium_sel {
                    3 => {
                        info!(ctx, "switched to light medium");
                        medium_selection = MediumSelection::Light
                    }
                    7 => {
                        info!(ctx, "switched to radio medium");
                        medium_selection = MediumSelection::Radio
                    }
                    _ => {}
                };
            }
        }
    }
    */

    match unsafe { (*iphdr).proto } {
        IpProto::Tcp => {
            let tcphdr = ptr_at_mut::<TcpHdr>(ctx, EthHdr::LEN + Ipv4Hdr::LEN)
                .ok_or(xdp_action::XDP_PASS)?;
            return Ok(xdp_action::XDP_PASS);
        }

        IpProto::Udp => {
            return Ok(xdp_action::XDP_PASS);
        }

        IpProto::Icmp => {}

        _ => return Ok(xdp_action::XDP_PASS),
    };

    /*
    unsafe {
        // do cheksum calculation first before rewriting old ip
        update_ipv4_csum(&mut (*iphdr).check, (*iphdr).dst_addr, client.ip);
        (*iphdr).dst_addr = client.ip;
        (*ethhdr).dst_addr = client.mac;
    }
    */

    //determine if we are redirecting based off handover packet or manually set by user
    /*
    return match medium_selection {
        MediumSelection::Radio => unsafe {
            //debug!(ctx, "sending to plc");
            (*ethhdr).src_addr = ifaces.plc_iface.mac;
            Ok(bpf_redirect(ifaces.plc_iface.idx, 0) as u32)
        },
        MediumSelection::Light => unsafe {
            //debug!(ctx, "sending to wifi");
            Ok(bpf_redirect(ifaces.wifi_iface.idx, 0) as u32)
        },
    };
    */
    return Ok(xdp_action::XDP_PASS);
}
