#![no_std]
#![no_main]

use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap},
};
use mrs_common::{IpMacMap, ClientMap, HandoverParams, IfaceMap, UserParams};

// keep all maps here

#[map]
pub static IPMAC_MAP: HashMap<[u8;6], u32> HashMap::<[u8;6],u32>::with_max_entries(254, 0);

#[map] // in-use
pub static IFACE_MAP: Array<IfaceMap> = Array::<IfaceMap>::with_max_entries(1, 0);

#[map]
pub static CLIENT_MAP: Array<ClientMap> = Array::<ClientMap>::with_max_entries(1, 0);

#[map]
pub static REDIRECT_MAP: Array<RedirectOpts> = Array::<RedirectOpts>::with_max_entries(1, 0);

#[map]
pub static USER_PARAMS_MAP: Array<UserParams> = Array::<UserParams>::with_max_entries(1, 0);

// TODO: Remove after demo
#[map]
pub static HANDOVER_MAP: Array<HandoverParams> = Array::<HandoverParams>::with_max_entries(1, 0);

#[map]
// cache of the outside mac router
pub static MAC_CACHE_MAP: Array<MacCache> = Array::<MacCache>::with_max_entries(1, 0);

#[map]
pub static ARP_CACHE_MAP: HashMap<u32, [u8; 6]> =
    HashMap::<u32, [u8; 6]>::with_max_entries(1024, 0);

#[map]
pub static ARP_CLIENT_REQUESTS: HashMap<u32, [u8; 6]> = 
    HashMap::<u32, [u8; 6]>::with_max_entries(1024, 0);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MacCache {
    addr: [u8; 6],
}

#[derive(Clone, Copy)]
pub enum RedirectOpts {
    WIFI,
    PLC,
}

// include these guys
mod progs;
mod utils;
